# Copyright 2013 OpenStack Foundation
# All Rights Reserved.
#
#    Licensed under the Apache License, Version 2.0 (the "License"); you may
#    not use this file except in compliance with the License. You may obtain
#    a copy of the License at
#
#         http://www.apache.org/licenses/LICENSE-2.0
#
#    Unless required by applicable law or agreed to in writing, software
#    distributed under the License is distributed on an "AS IS" BASIS, WITHOUT
#    WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied. See the
#    License for the specific language governing permissions and limitations
#    under the License.

"""
/hosts endpoint for Daisy v1 API
"""

from oslo_config import cfg
from oslo_log import log as logging
from webob.exc import HTTPBadRequest
from webob.exc import HTTPConflict
from webob.exc import HTTPForbidden
from webob.exc import HTTPNotFound
from webob import Response

from daisy.api import policy
import daisy.api.v1
from daisy.api.v1 import controller
from daisy.api.v1 import filters
from daisy.common import exception
from daisy.common import property_utils
from daisy.common import utils
from daisy.common import wsgi
from daisy import i18n
from daisy import notifier
import daisy.registry.client.v1.api as registry

LOG = logging.getLogger(__name__)
_ = i18n._
_LE = i18n._LE
_LI = i18n._LI
_LW = i18n._LW
SUPPORTED_PARAMS = daisy.api.v1.SUPPORTED_PARAMS
SUPPORTED_FILTERS = daisy.api.v1.SUPPORTED_FILTERS
ACTIVE_IMMUTABLE = daisy.api.v1.ACTIVE_IMMUTABLE

CONF = cfg.CONF
CONF.import_opt('disk_formats', 'daisy.common.config', group='image_format')
CONF.import_opt('container_formats', 'daisy.common.config',
                group='image_format')
CONF.import_opt('image_property_quota', 'daisy.common.config')

class Controller(controller.BaseController):
    """
    WSGI controller for networks resource in Daisy v1 API

    The networks resource API is a RESTful web service for host data. The API
    is as follows::

        GET  /networks -- Returns a set of brief metadata about networks
        GET  /networks/detail -- Returns a set of detailed metadata about
                              networks
        HEAD /networks/<ID> -- Return metadata about an host with id <ID>
        GET  /networks/<ID> -- Return host data for host with id <ID>
        POST /networks -- Store host data and return metadata about the
                        newly-stored host
        PUT  /networks/<ID> -- Update host metadata and/or upload host
                            data for a previously-reserved host
        DELETE /networks/<ID> -- Delete the host with id <ID>
    """

    def __init__(self):
        self.notifier = notifier.Notifier()
        registry.configure_registry_client()
        self.policy = policy.Enforcer()
        if property_utils.is_property_protection_enabled():
            self.prop_enforcer = property_utils.PropertyRules(self.policy)
        else:
            self.prop_enforcer = None

    def _enforce(self, req, action, target=None):
        """Authorize an action against our policies"""
        if target is None:
            target = {}
        try:
            self.policy.enforce(req.context, action, target)
        except exception.Forbidden:
            raise HTTPForbidden()

    def _raise_404_if_network_deleted(self, req, network_id):
        network = self.get_network_meta_or_404(req, network_id)
        if network['deleted']:
            msg = _("Network with identifier %s has been deleted.") % network_id
            raise HTTPNotFound(msg)
    def _raise_404_if_cluster_delete(self, req, cluster_id):
        cluster_id = self.get_cluster_meta_or_404(req, cluster_id)
        if cluster_id['deleted']:
            msg = _("cluster_id with identifier %s has been deleted.") % cluster_id
            raise HTTPNotFound(msg)

    def _get_network_name_by_cluster_id(self, context, cluster_id):
        networks = registry.get_networks_detail(context, cluster_id)
        network_name_list = []
        for network in networks:
            network_name_list.append(network['name'])
        return network_name_list


    def _get_filters(self, req):
        """
        Return a dictionary of query param filters from the request

        :param req: the Request object coming from the wsgi layer
        :retval a dict of key/value filters
        """
        query_filters = {}
        for param in req.params:
            if param in SUPPORTED_FILTERS:
                query_filters[param] = req.params.get(param)
                if not filters.validate(param, query_filters[param]):
                    raise HTTPBadRequest(_('Bad value passed to filter '
                                           '%(filter)s got %(val)s')
                                         % {'filter': param,
                                            'val': query_filters[param]})
        return query_filters

    def _get_query_params(self, req):
        """
        Extracts necessary query params from request.

        :param req: the WSGI Request object
        :retval dict of parameters that can be used by registry client
        """
        params = {'filters': self._get_filters(req)}

        for PARAM in SUPPORTED_PARAMS:
            if PARAM in req.params:
                params[PARAM] = req.params.get(PARAM)
        return params
        
    def validate_ip_fromat(self, ip_str):
        '''
        valid ip_str format = '10.43.178.9'
        invalid ip_str format : '123. 233.42.12', spaces existed in field
                                '3234.23.453.353', out of range
                                '-2.23.24.234', negative number in field
                                '1.2.3.4d', letter in field
                                '10.43.1789', invalid format
        '''
        valid_fromat = False
        if ip_str.count('.') == 3 and \
            all(num.isdigit() and 0<=int(num)<256 for num in ip_str.rstrip().split('.')):
            valid_fromat = True
        if valid_fromat == False:
            msg = (_("%s invalid ip format!") % ip_str)
            LOG.warn(msg)
            raise HTTPForbidden(msg)
    
    def _ip_into_int(self, ip):
        """
        Switch ip string to decimalism integer..
        :param ip: ip string
        :return: decimalism integer
        """
        return reduce(lambda x, y: (x<<8)+y, map(int, ip.split('.')))

    def _is_in_network_range(self, ip, network):
        """
        Check ip is in range
        :param ip: Ip will be checked, like:192.168.1.2.
        :param network: Ip range,like:192.168.0.0/24.
        :return: If ip in range,return True,else return False.
        """
        network = network.split('/')
        mask = ~(2**(32 - int(network[1])) - 1)
        return (_ip_into_int(ip) & mask) == (_ip_into_int(network[0]) & mask)

    def check_network_name(self, req, network_list, network_meta, is_update = False):
        """
        Network name is match case and uniqueness.
        :param req:
        :param network_list:
        :param network_meta:
        :return:
        """
        network_name = network_meta["name"]

        # network name don't match case
        for network in network_list['networks']:
            if network_name == network['name'] and is_update:
                return

        network_name_list = \
            [network['name'].lower() for network in network_list['networks']
             if network.get('name', None) and network_meta['network_type'] == network['network_type']]
        if network_name.lower() in network_name_list:
            msg = _("Name of network isn't match case and %s already exits in the cluster." % network_name)
            raise HTTPConflict(msg, request=req, content_type="text/plain")

        if not is_update:
            # Input networks type can't be same with db record which is all ready exit,
            # excepy PRIVATE network.
            network_type_exist_list = \
                [network['network_type'] for network in network_list['networks']
                 if network.get('network_type', None) and network['network_type'] != "PRIVATE"]
            if  network_meta.get("network_type", None) in network_type_exist_list:
                msg = _("The type of networks:%s is same with db record which is "
                        "all ready exit,excepy PRIVATE network." % network_name)
                raise HTTPConflict(msg, request=req, content_type="text/plain")

    @utils.mutating
    def add_network(self, req, network_meta):
        """
        Adds a new networks to Daisy.

        :param req: The WSGI/Webob Request object
        :param image_meta: Mapping of metadata about network

        :raises HTTPBadRequest if x-host-name is missing
        """
        self._enforce(req, 'add_network')
        cluster_id = network_meta.get('cluster_id')
        if cluster_id:
            self._raise_404_if_cluster_delete(req, cluster_id)
            network_list = self.detail(req, cluster_id)
            self.check_network_name(req, network_list, network_meta)
        else:
            if network_meta.get('type') != "template":
                raise HTTPBadRequest(explanation="cluster id must be given", request=req)
                
        if network_meta.get('ip_ranges'):
            ip_ranges = eval(network_meta['ip_ranges'])
            last_ip_range_end = 0
            int_ip_ranges_list = list()
            sorted_int_ip_ranges_list = list()
            for ip_pair in ip_ranges:
                if ['start', 'end'] != ip_pair.keys():
                    msg = (_("IP range was not start with 'start:' or end with 'end:'."))
                    LOG.warn(msg)
                    raise HTTPForbidden(msg)
                ip_start = ip_pair['start'] 
                ip_end = ip_pair['end']
                self.validate_ip_fromat(ip_start)   #check ip format
                self.validate_ip_fromat(ip_end) 
                #transform ip format to int when the string format is valid
                int_ip_start = self._ip_into_int(ip_start)
                int_ip_end = self._ip_into_int(ip_end)
                
                if int_ip_start > int_ip_end:
                    msg = (_("Wrong ip range format."))
                    LOG.warn(msg)
                    raise HTTPForbidden(msg)
                int_ip_ranges_list.append([int_ip_start, int_ip_end])
            sorted_int_ip_ranges_list = sorted(int_ip_ranges_list, key=lambda x : x[0])
            
            for int_ip_range in sorted_int_ip_ranges_list:
                if last_ip_range_end and last_ip_range_end >= int_ip_range[0]:
                    msg = (_("Between ip ranges can not be overlap."))
                    LOG.warn(msg)  # such as "[10, 15], [12, 16]", last_ip_range_end >= int_ip_range[0], this ip ranges were overlap
                    raise HTTPForbidden(msg)
                else:
                    last_ip_range_end = int_ip_range[1]
            
        network_meta = registry.add_network_metadata(req.context, network_meta)
        return {'network_meta': network_meta}

    @utils.mutating
    def delete_network(self, req, network_id):
        """
        Deletes a network from Daisy.

        :param req: The WSGI/Webob Request object
        :param image_meta: Mapping of metadata about host

        :raises HTTPBadRequest if x-host-name is missing
        """
        self._enforce(req, 'delete_network')
        #self._raise_404_if_cluster_deleted(req, cluster_id)
        self._raise_404_if_network_deleted(req, network_id)

        try:
            registry.delete_network_metadata(req.context, network_id)
        except exception.NotFound as e:
            msg = (_("Failed to find network to delete: %s") %
                   utils.exception_to_str(e))
            LOG.warn(msg)
            raise HTTPNotFound(explanation=msg,
                               request=req,
                               content_type="text/plain")
        except exception.Forbidden as e:
            msg = (_("Forbidden to delete network: %s") %
                   utils.exception_to_str(e))
            LOG.warn(msg)
            raise HTTPForbidden(explanation=msg,
                                request=req,
                                content_type="text/plain")
        except exception.InUseByStore as e:
            msg = (_("Network %(id)s could not be deleted because it is in use: "
                     "%(exc)s") % {"id": id, "exc": utils.exception_to_str(e)})
            LOG.warn(msg)
            raise HTTPConflict(explanation=msg,
                               request=req,
                               content_type="text/plain")
        else:
            #self.notifier.info('host.delete', host)
            return Response(body='', status=200)

    @utils.mutating
    def get_network(self, req, id):
        """
        Returns metadata about an network in the HTTP headers of the
        response object

        :param req: The WSGI/Webob Request object
        :param id: The opaque host identifier

        :raises HTTPNotFound if host metadata is not available to user
        """
        self._enforce(req, 'get_network')
        network_meta = self.get_network_meta_or_404(req, id)
        return {'network_meta': network_meta}

    def detail(self, req, id):
        """
        Returns detailed information for all available hosts

        :param req: The WSGI/Webob Request object
        :retval The response body is a mapping of the following form::

            {'networks': [
                {'id': <ID>,
                 'name': <NAME>,
                 'description': <DESCRIPTION>,
                 'created_at': <TIMESTAMP>,
                 'updated_at': <TIMESTAMP>,
                 'deleted_at': <TIMESTAMP>|<NONE>,}, ...
            ]}
        """
        cluster_id = self._raise_404_if_cluster_delete(req, id)
        self._enforce(req, 'get_networks')
        params = self._get_query_params(req)
        try:
            networks = registry.get_networks_detail(req.context, id)
        except exception.Invalid as e:
            raise HTTPBadRequest(explanation=e.msg, request=req)
        return dict(networks=networks)

    @utils.mutating
    def update_network(self, req, network_id, network_meta):
        """
        Updates an existing host with the registry.

        :param request: The WSGI/Webob Request object
        :param id: The opaque image identifier

        :retval Returns the updated image information as a mapping
        """

        self._enforce(req, 'update_network')
        #orig_cluster_meta = self.get_cluster_meta_or_404(req, cluster_id)
        orig_network_meta = self.get_network_meta_or_404(req, network_id)
        # Do not allow any updates on a deleted network.
        if orig_network_meta['deleted']:
            msg = _("Forbidden to update deleted host.")
            raise HTTPForbidden(explanation=msg,
                                request=req,
                                content_type="text/plain")

        cluster_id = network_meta.get('cluster_id', None)
        network_name = network_meta.get('name', None)
        if not cluster_id:
            cluster_id = orig_network_meta['cluster_id']

        network_type = network_meta.get('network_type', None)
        if network_name and cluster_id:
            self._raise_404_if_cluster_delete(req, cluster_id)
            network_list = self.detail(req, cluster_id)
            network_meta['network_type'] = \
                orig_network_meta['network_type'] if not network_type else network_type
            self.check_network_name(req, network_list, network_meta, True)
            
        if network_meta.get('ip_ranges'):
            ip_ranges = eval(network_meta['ip_ranges'])
            last_ip_range_end = 0
            int_ip_ranges_list = list()
            sorted_int_ip_ranges_list = list()
            for ip_pair in ip_ranges:
                if ['start', 'end'] != ip_pair.keys():
                    msg = (_("IP range was not start with 'start:' or end with 'end:'."))
                    LOG.warn(msg)
                    raise HTTPForbidden(msg)
                ip_start = ip_pair['start'] 
                ip_end = ip_pair['end']
                self.validate_ip_fromat(ip_start)   #check ip format
                self.validate_ip_fromat(ip_end) 
                #transform ip format to int when the string format is valid
                int_ip_start = self._ip_into_int(ip_start)
                int_ip_end = self._ip_into_int(ip_end)
                
                if int_ip_start > int_ip_end:
                    msg = (_("Wrong ip range format."))
                    LOG.warn(msg)
                    raise HTTPForbidden(msg)
                int_ip_ranges_list.append([int_ip_start, int_ip_end])
            sorted_int_ip_ranges_list = sorted(int_ip_ranges_list, key=lambda x : x[0])
            LOG.warn("sorted_int_ip_ranges_list: "% sorted_int_ip_ranges_list)
            for int_ip_range in sorted_int_ip_ranges_list:
                if last_ip_range_end and last_ip_range_end >= int_ip_range[0]:
                    msg = (_("Between ip ranges can not be overlap."))
                    LOG.warn(msg)  # such as "[10, 15], [12, 16]", last_ip_range_end >= int_ip_range[0], this ip ranges were overlap
                    raise HTTPForbidden(msg)
                else:
                    last_ip_range_end = int_ip_range[1]

        try:
            network_meta = registry.update_network_metadata(req.context,
                                                            network_id,
                                                            network_meta)
        except exception.Invalid as e:
            msg = (_("Failed to update network metadata. Got error: %s") %
                   utils.exception_to_str(e))
            LOG.warn(msg)
            raise HTTPBadRequest(explanation=msg,
                                 request=req,
                                 content_type="text/plain")
        except exception.NotFound as e:
            msg = (_("Failed to find network to update: %s") %
                   utils.exception_to_str(e))
            LOG.warn(msg)
            raise HTTPNotFound(explanation=msg,
                               request=req,
                               content_type="text/plain")
        except exception.Forbidden as e:
            msg = (_("Forbidden to update network: %s") %
                   utils.exception_to_str(e))
            LOG.warn(msg)
            raise HTTPForbidden(explanation=msg,
                                request=req,
                                content_type="text/plain")
        except (exception.Conflict, exception.Duplicate) as e:
            LOG.warn(utils.exception_to_str(e))
            raise HTTPConflict(body=_('Network operation conflicts'),
                               request=req,
                               content_type='text/plain')
        else:
            self.notifier.info('network.update', network_meta)

        return {'network_meta': network_meta}

class HostDeserializer(wsgi.JSONRequestDeserializer):
    """Handles deserialization of specific controller method requests."""

    def _deserialize(self, request):
        result = {}
        result["network_meta"] = utils.get_network_meta(request)
        return result

    def add_network(self, request):
        return self._deserialize(request)

    def update_network(self, request):
        return self._deserialize(request)

class HostSerializer(wsgi.JSONResponseSerializer):
    """Handles serialization of specific controller method responses."""

    def __init__(self):
        self.notifier = notifier.Notifier()

    def add_network(self, response, result):
        network_meta = result['network_meta']
        response.status = 201
        response.headers['Content-Type'] = 'application/json'
        response.body = self.to_json(dict(network=network_meta))
        return response

    def delete_network(self, response, result):
        network_meta = result['network_meta']
        response.status = 201
        response.headers['Content-Type'] = 'application/json'
        response.body = self.to_json(dict(network=network_meta))
        return response

    def get_network(self, response, result):
        network_meta = result['network_meta']
        response.status = 201
        response.headers['Content-Type'] = 'application/json'
        response.body = self.to_json(dict(network=network_meta))
        return response

def create_resource():
    """Hosts resource factory method"""
    deserializer = HostDeserializer()
    serializer = HostSerializer()
    return wsgi.Resource(Controller(), deserializer, serializer)

