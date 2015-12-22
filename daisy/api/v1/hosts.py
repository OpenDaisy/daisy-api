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
import subprocess
from oslo_config import cfg
from oslo_log import log as logging
from webob.exc import HTTPBadRequest
from webob.exc import HTTPConflict
from webob.exc import HTTPForbidden
from webob.exc import HTTPNotFound
from webob import Response
from collections import Counter
from webob.exc import HTTPServerError
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
    WSGI controller for hosts resource in Daisy v1 API

    The hosts resource API is a RESTful web service for host data. The API
    is as follows::

        GET  /nodes -- Returns a set of brief metadata about hosts
        GET  /nodes -- Returns a set of detailed metadata about
                              hosts
        HEAD /nodes/<ID> -- Return metadata about an host with id <ID>
        GET  /nodes/<ID> -- Return host data for host with id <ID>
        POST /nodes -- Store host data and return metadata about the
                        newly-stored host
        PUT  /nodes/<ID> -- Update host metadata and/or upload host
                            data for a previously-reserved host
        DELETE /nodes/<ID> -- Delete the host with id <ID>
    """
    support_resource_type = ['baremetal', 'server', 'docker']
    
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
        if network is None or network['deleted']:
            msg = _("Network with identifier %s has been deleted.") % network_id
            raise HTTPNotFound(msg)

    def _raise_404_if_cluster_deleted(self, req, cluster_id):
        cluster = self.get_cluster_meta_or_404(req, cluster_id)
        if cluster is None or cluster['deleted']:
            msg = _("Cluster with identifier %s has been deleted.") % cluster_id
            raise HTTPNotFound(msg)

    def _raise_404_if_role_deleted(self, req, role_id):
        role = self.get_role_meta_or_404(req, role_id)
        if role is None or role['deleted']:
            msg = _("Cluster with identifier %s has been deleted.") % role_id
            raise HTTPNotFound(msg)


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

    @utils.mutating
    def add_host(self, req, host_meta):
        """
        Adds a new host to Daisy

        :param req: The WSGI/Webob Request object
        :param image_meta: Mapping of metadata about host

        :raises HTTPBadRequest if x-host-name is missing
        """
        # if host is update in '_verify_interface_among_hosts', no need add host continue.
        cluster_id = host_meta.get('cluster', None)
        if self._verify_interface_among_hosts(req, cluster_id, host_meta):
            return {'host_meta': host_meta}

        self._enforce(req, 'add_host')
        if host_meta.has_key('resource_type'):
            if host_meta['resource_type'] not in self.support_resource_type:
                msg = "resource type is not supported, please use it in %s" % self.support_resource_type
                raise HTTPBadRequest(explanation=msg,
                                     request=req,
                                     content_type="text/plain")
        else:
            host_meta['resource_type'] = 'baremetal'

        if cluster_id:
            self.get_cluster_meta_or_404(req, cluster_id)
        if host_meta.has_key('role') and host_meta['role']:
            role_id_list = []
            host_roles=[]
            if host_meta.has_key('cluster'):
                params = self._get_query_params(req)
                role_list = registry.get_roles_detail(req.context, **params)
                for role_name in role_list:
                    if role_name['cluster_id'] == host_meta['cluster']:
                        host_roles = list(eval(host_meta['role']))
                        for host_role in host_roles:
                            if role_name['name'] == host_role:
                                role_id_list.append(role_name['id'])
                                continue
                if len(role_id_list) != len(host_roles):
                    msg = "The role of params %s is not exist, please use the right name" % host_roles
                    raise HTTPBadRequest(explanation=msg,
                                         request=req,
                                         content_type="text/plain")
                host_meta['role'] = role_id_list
            else:
                msg = "cluster params is none"
                raise HTTPBadRequest(explanation=msg,
                                     request=req,
                                     content_type="text/plain")

        assigned_networks = {}
        if host_meta.has_key('interfaces'):
            network_id_list = []
            orig_keys = list(eval(host_meta['interfaces']))
            for network in orig_keys:
                if network.has_key('is_deployment'):
                    if network['is_deployment'] == "True" or network['is_deployment'] == True:
                        network['is_deployment'] = 1
                    else:
                        network['is_deployment'] = 0
                if network.has_key('assigned_networks') and network['assigned_networks'] != [''] and network['assigned_networks']:
                    if host_meta.has_key('cluster'):
                        network_list = registry.get_networks_detail(req.context, host_meta['cluster'])
                        for network_name in list(network['assigned_networks']):
                            lenth = len(network_id_list)
                            for network_info in network_list:
                                if network_name == network_info['name']:
                                    network_id_list.append(network_info['id'])

                                    if network_info.get('id', None) \
                                        and network_info.get('name', None) \
                                        and network.get('name', None):
                                        assigned_networks[network_info['id']] = \
                                            [network_info.get('name', None), network.get('name', None)]
                            if lenth == len(network_id_list):
                                msg="The network of params %s is not exist, please use the right name" % network_name
                                raise HTTPBadRequest(explanation=msg,
                                                     request=req,
                                                     content_type="text/plain")
                        network['assigned_networks'] = network_id_list
                        # by cluster id and network_name search network table
                        registry.update_phyname_of_network(req.context, assigned_networks)
                    else:
                        msg = "cluster params is none"
                        raise HTTPBadRequest(explanation=msg,
                                             request=req,
                                             content_type="text/plain")
                if network.has_key('mac') and network.has_key('ip'):
                    host_infos = registry.get_host_interface(req.context, host_meta)
                    for host_info in host_infos:
                        if host_info.has_key('host_id'):
                            host_meta["id"] = host_info['host_id']

        if host_meta.has_key('os_status'):
            if host_meta['os_status'] not in ['init', 'installing', 'active', 'failed', 'none']:
                msg = "os_status is not valid."
                raise HTTPBadRequest(explanation=msg,
                                     request=req,
                                     content_type="text/plain")
                
        if host_meta.has_key('ipmi_addr') and host_meta['ipmi_addr']:
            if not host_meta.has_key('ipmi_user'):
                host_meta['ipmi_user'] = 'zteroot'
            if not host_meta.has_key('ipmi_passwd'):
                host_meta['ipmi_passwd'] = 'superuser'

        host_meta = registry.add_host_metadata(req.context, host_meta)

        return {'host_meta': host_meta}

    @utils.mutating
    def delete_host(self, req, id):
        """
        Deletes a host from Daisy.

        :param req: The WSGI/Webob Request object
        :param image_meta: Mapping of metadata about host

        :raises HTTPBadRequest if x-host-name is missing
        """
        self._enforce(req, 'delete_host')

        try:
            registry.delete_host_metadata(req.context, id)
        except exception.NotFound as e:
            msg = (_("Failed to find host to delete: %s") %
                   utils.exception_to_str(e))
            LOG.warn(msg)
            raise HTTPNotFound(explanation=msg,
                               request=req,
                               content_type="text/plain")
        except exception.Forbidden as e:
            msg = (_("Forbidden to delete host: %s") %
                   utils.exception_to_str(e))
            LOG.warn(msg)
            raise HTTPForbidden(explanation=msg,
                                request=req,
                                content_type="text/plain")
        except exception.InUseByStore as e:
            msg = (_("Host %(id)s could not be deleted because it is in use: "
                     "%(exc)s") % {"id": id, "exc": utils.exception_to_str(e)})
            LOG.warn(msg)
            raise HTTPConflict(explanation=msg,
                               request=req,
                               content_type="text/plain")
        else:
            #self.notifier.info('host.delete', host)
            return Response(body='', status=200)

    @utils.mutating
    def get_host(self, req, id):
        """
        Returns metadata about an host in the HTTP headers of the
        response object

        :param req: The WSGI/Webob Request object
        :param id: The opaque host identifier

        :raises HTTPNotFound if host metadata is not available to user
        """
        self._enforce(req, 'get_host')
        host_meta = self.get_host_meta_or_404(req, id)
        return {'host_meta': host_meta}

    def detail(self, req):
        """
        Returns detailed information for all available nodes

        :param req: The WSGI/Webob Request object
        :retval The response body is a mapping of the following form::

            {'nodes': [
                {'id': <ID>,
                 'name': <NAME>,
                 'description': <DESCRIPTION>,
                 'created_at': <TIMESTAMP>,
                 'updated_at': <TIMESTAMP>,
                 'deleted_at': <TIMESTAMP>|<NONE>,}, ...
            ]}
        """
        self._enforce(req, 'get_hosts')
        params = self._get_query_params(req)
        try:
            nodes = registry.get_hosts_detail(req.context, **params)
        except exception.Invalid as e:
            raise HTTPBadRequest(explanation=e.msg, request=req)
        return dict(nodes=nodes)

    def _verify_interface_in_same_host(self, interfaces, id = None):
        """
        Verify interface in the input host.
        :param interface: host interface info
        :return:
        """
        # verify interface among the input host
        interfaces = eval(interfaces)
        same_mac_list = [interface1['name']
                         for interface1 in interfaces for interface2 in interfaces
                         if interface1.get('name', None) and interface1.get('mac', None) and
                            interface2.get('name', None) and interface2.get('mac', None) and
                            interface1.get('type', None) and interface2.get('type', None) and
                         interface1['name'] != interface2['name'] and interface1['mac'] == interface2['mac']
                         and interface1['type'] != "bond" and interface2['type'] != "bond"]
        # Notice:If interface with same 'mac' is illegal,we need delete code #1,and raise exception in 'if' block.
        # This code block is just verify for early warning.
        if same_mac_list:
            msg = "%s%s" % ("" if not id else "Host id:%s." % id,
                            "The nic name of interface [%s] with same mac,please check!" %
                            ",".join(same_mac_list))
            LOG.warn(msg)

        # 1-----------------------------------------------------------------
        # if interface with same 'pci', raise exception
        same_pci_list = [interface1['name']
                         for interface1 in interfaces for interface2 in interfaces
                         if interface1.get('name', None) and interface1.get('pci', None) and
                             interface2.get('name', None) and interface2.get('pci', None) and
                            interface1.get('type', None) and interface2.get('type', None) and
                         interface1['name'] != interface2['name'] and interface1['pci'] == interface2['pci']
                         and interface1['type'] != "bond" and interface2['type'] != "bond"]

        if same_pci_list:
            msg = "The nic name of interface [%s] with same pci,please check!" % ",".join(same_pci_list)
            raise HTTPForbidden(explanation = msg)
        # 1-----------------------------------------------------------------

    def _verify_interface_among_hosts(self, req, cluster_id, host_meta):
        """
        Verify interface among the hosts in cluster
        :param req:
        :param cluster_id:
        :param host_meta:
        :return:
        """
        # If true, the host need update, not add and update is successful.
        host_is_update = False
        if not host_meta.get('interfaces', None):
            return host_is_update
        self._verify_interface_in_same_host(host_meta['interfaces'])

        # host pxe interface info
        interfaces = eval(host_meta['interfaces'])
        input_host_pxe_info = [interface
                               for interface in interfaces
                               if interface.get('is_deployment', None) == "True"]

        # In default,we think there is only one pxe interface.
        # If it not only the exception will be raise.
        if not input_host_pxe_info:
            LOG.info("<<<The host %s don't have pxe interface.>>>" % host_meta.get('name', None))
            return host_is_update

        if len(input_host_pxe_info) > 1:
            msg = ("There are two different pxe nics among the same host,it isn't allowed.")
            raise HTTPServerError(explanation = msg)

        if not cluster_id:
            return host_is_update

        # verify interface between exist host and input host in cluster
        list_params = {
            'sort_key': u'name',
            'sort_dir': u'asc',
            'limit': u'20',
            'filters': {u'cluster_id': cluster_id}
        }
        exist_nodes = registry.get_hosts_detail(req.context, **list_params)

        input_host_pxe_info = input_host_pxe_info[0]
        for exist_node in exist_nodes:
            id = exist_node.get('id', None)
            exist_node_info = self.get_host(req, id).get('host_meta', None)
            if not exist_node_info.get('interfaces', None):
                continue

            for interface in exist_node_info['interfaces']:
                if interface.get('mac', None) != input_host_pxe_info.get('mac', None):
                    continue
                if exist_node.get('dmi_uuid', None) != host_meta.get('dmi_uuid', None):
                    msg = "The 'mac' of host interface is exist in db, but 'dmi_uuid' is different." \
                          "We think you want update the host, but the host can't find."
                    raise HTTPForbidden(explanation = msg)

                host_meta['id'] = id
                host_meta['cluster_id'] = id
                self.update_host(req, id, host_meta)
                LOG.info("<<<FUN:verify_interface, host:%s is already update.>>>" % id)
                host_is_update = True
        return host_is_update
    def _get_swap_lv_size_m(self, memory_size_m):
        if memory_size_m <= 4096:
            swap_lv_size_m = 4096
        elif memory_size_m <= 16384:
            swap_lv_size_m = 8192
        elif memory_size_m <= 65536:
            swap_lv_size_m = 32768
        else:
            swap_lv_size_m = 65536
        return swap_lv_size_m
    
    @utils.mutating
    def update_host(self, req, id, host_meta):
        """
        Updates an existing host with the registry.

        :param request: The WSGI/Webob Request object
        :param id: The opaque image identifier

        :retval Returns the updated image information as a mapping
        """
        if host_meta.get('interfaces', None):
            self._verify_interface_in_same_host(host_meta['interfaces'], id)

        self._enforce(req, 'update_host')
        orig_host_meta = self.get_host_meta_or_404(req, id)
        # Do not allow any updates on a deleted image.
        # Fix for LP Bug #1060930
        if orig_host_meta['deleted']:
            msg = _("Forbidden to update deleted host.")
            raise HTTPForbidden(explanation=msg,
                                request=req,
                                content_type="text/plain")

        if host_meta.has_key('cluster'):
            self.get_cluster_meta_or_404(req, host_meta['cluster'])
    
        if (host_meta.has_key('resource_type') and
            host_meta['resource_type'] not in self.support_resource_type):
            msg = "resource type is not supported, please use it in %s" % self.support_resource_type
            raise HTTPNotFound(msg)
            
        if orig_host_meta.get('disks',None):
            if host_meta.get('os_status',None) != 'init' and orig_host_meta.get('os_status',None) == 'active':
                host_meta['root_disk'] = orig_host_meta['root_disk']
            else:
                if host_meta.get('root_disk',None):
                    root_disk = host_meta['root_disk']
                elif orig_host_meta.get('root_disk',None):
                    root_disk = str(orig_host_meta['root_disk'])
                else:
                    host_meta['root_disk'] = 'sda'
                    root_disk = host_meta['root_disk']
                if root_disk not in orig_host_meta['disks'].keys():
                    msg = "There is no disk named %s" % root_disk
                    raise HTTPBadRequest(explanation=msg,
                                        request=req,
                                        content_type="text/plain")
        else:
            host_meta['root_disk'] = orig_host_meta['root_disk']

        if orig_host_meta.get('disks',None):
            if host_meta.get('os_status',None) != 'init' and orig_host_meta.get('os_status',None) == 'active':
                host_meta['root_lv_size'] = orig_host_meta['root_lv_size']
            else:
                if host_meta.get('root_lv_size',None):
                    root_lv_size = host_meta['root_lv_size']
                elif orig_host_meta.get('root_lv_size',None):
                    root_lv_size = str(orig_host_meta['root_lv_size'])
                else:
                    host_meta['root_lv_size'] = '51200'
                    root_lv_size = host_meta['root_lv_size']
                    
                if root_lv_size.isdigit():
                    root_lv_size=int(root_lv_size)
                    root_disk_storage_size_b_str = str(orig_host_meta['disks']['%s' %root_disk]['size'])
                    root_disk_storage_size_b_int = int(root_disk_storage_size_b_str.strip().split()[0])
                    root_disk_storage_size_m = root_disk_storage_size_b_int//(1024*1024)
                    boot_partition_m = 400
                    redundant_partiton_m = 100
                    free_root_disk_storage_size_m = root_disk_storage_size_m - boot_partition_m - redundant_partiton_m
                    if (root_lv_size/4)*4 > free_root_disk_storage_size_m:
                        msg = "root_lv_size of %s is larger than the free_root_disk_storage_size."%orig_host_meta['id']
                        raise HTTPForbidden(explanation=msg,
                                            request=req,
                                            content_type="text/plain")
                    if (root_lv_size/4)*4 < 51200:
                        msg = "root_lv_size of %s is too small ,it must be larger than 51200M."%orig_host_meta['id']
                        raise HTTPForbidden(explanation=msg,
                                            request=req,
                                            content_type="text/plain")
                else:
                    msg = (_("root_lv_size of %s is wrong,please input a number and it must be positive number") %orig_host_meta['id'])
                    raise HTTPForbidden(explanation=msg,
                                        request=req,
                                        content_type="text/plain")
        else:
            host_meta['root_lv_size'] = orig_host_meta['root_lv_size']
            
        if orig_host_meta.get('disks',None):
            if host_meta.get('os_status',None) != 'init' and orig_host_meta.get('os_status',None) == 'active':
                host_meta['swap_lv_size'] = orig_host_meta['swap_lv_size']
            else:
                if host_meta.get('swap_lv_size',None):
                    swap_lv_size = host_meta['swap_lv_size']
                elif orig_host_meta.get('swap_lv_size',None):
                    swap_lv_size = str(orig_host_meta['swap_lv_size'])
                else:
                    if not orig_host_meta.get('memory',None):
                        msg = "there is no memory in %s" %orig_host_meta['id']
                        raise HTTPNotFound(msg)
                    memory_size_b_str = str(orig_host_meta['memory']['total'])
                    memory_size_b_int = int(memory_size_b_str.strip().split()[0])
                    memory_size_m = memory_size_b_int//1024
                    swap_lv_size_m = self._get_swap_lv_size_m(memory_size_m)
                    host_meta['swap_lv_size'] = str(swap_lv_size_m)
                    swap_lv_size = host_meta['swap_lv_size']
                if swap_lv_size.isdigit():
                    swap_lv_size=int(swap_lv_size)
                    disk_storage_size_b = 0
                    for key in orig_host_meta['disks']:
                        stroage_size_str = orig_host_meta['disks'][key]['size']
                        stroage_size_b_int = int(stroage_size_str.strip().split()[0])
                        disk_storage_size_b = disk_storage_size_b + stroage_size_b_int
                    disk_storage_size_m = disk_storage_size_b/(1024*1024)
                    boot_partition_m = 400
                    redundant_partiton_m = 100
                    free_disk_storage_size_m = disk_storage_size_m - boot_partition_m - redundant_partiton_m - (root_lv_size/4)*4
                    if (swap_lv_size/4)*4 > free_disk_storage_size_m:
                        msg = "swap_lv_size of %s is larger than the free_disk_storage_size."%orig_host_meta['id']
                        raise HTTPForbidden(explanation=msg,
                                            request=req,
                                            content_type="text/plain")
                    if (swap_lv_size/4)*4 < 2000:
                        msg = "swap_lv_size of %s is too small ,it must be larger than 2000M."%orig_host_meta['id']
                        raise HTTPForbidden(explanation=msg,
                                            request=req,
                                            content_type="text/plain")
                else:
                    msg = (_("swap_lv_size of %s is wrong,please input a number and it must be positive number") %orig_host_meta['id'])
                    raise HTTPForbidden(explanation=msg,
                                        request=req,
                                        content_type="text/plain")
        else:
            host_meta['swap_lv_size'] = orig_host_meta['swap_lv_size']
            
        if orig_host_meta.get('disks',None):
            if not host_meta.get('root_pwd',None) and not orig_host_meta.get('root_pwd',None):
                host_meta['root_pwd'] = 'ossdbg1'
        else:
            host_meta['root_pwd'] = orig_host_meta['root_pwd']

        if host_meta.has_key('role'):
            role_id_list = []
            if host_meta.has_key('cluster'):
                params = self._get_query_params(req)
                role_list = registry.get_roles_detail(req.context, **params)
                host_roles = list()
                for role_name in role_list:
                    if role_name['cluster_id'] == host_meta['cluster']:
                        host_roles = list(eval(host_meta['role']))
                        for host_role in host_roles:
                            if role_name['name'] == host_role:
                                role_id_list.append(role_name['id'])
                                continue
                if len(role_id_list) != len(host_roles) and host_meta['role'] != u"[u'']":
                    msg = "The role of params %s is not exist, please use the right name" % host_roles
                    raise HTTPNotFound(msg)
                host_meta['role'] = role_id_list
            else:
                msg = "cluster params is none"
                raise HTTPNotFound(msg)

        assigned_networks = {}
        if host_meta.has_key('interfaces'):
            network_id_list = []
            orig_keys = list(eval(host_meta['interfaces']))
            for network in orig_keys:
                if network.has_key('is_deployment'):
                    if network['is_deployment'] == "True" or network['is_deployment'] == True:
                        network['is_deployment'] = 1
                    else:
                        network['is_deployment'] = 0
                if network.has_key('assigned_networks') and network['assigned_networks'] != [''] and network['assigned_networks']:
                    if host_meta.has_key('cluster'):
                        network_list = registry.get_networks_detail(req.context, host_meta['cluster'])
                        for network_name in list(network['assigned_networks']):
                            lenth = len(network_id_list)
                            for network_info in network_list:
                                if network_name == network_info['name']:
                                    network_id_list.append(network_info['id'])

                                    if network_info.get('id', None) \
                                        and network_info.get('name', None) \
                                        and network.get('name', None):
                                        assigned_networks[network_info['id']] = \
                                            [network_info.get('name', None), network.get('name', None)]
                            if lenth == len(network_id_list):
                                msg="The network of params %s is not exist, please use the right name" % network_name
                                raise HTTPNotFound(msg)

                        network['assigned_networks'] = network_id_list
                        # by cluster id and network_name search network table
                        registry.update_phyname_of_network(req.context, assigned_networks)
                    else:
                        msg = "cluster params is none"
                        raise HTTPNotFound(msg)

        if host_meta.has_key('os_status'):
            if host_meta['os_status'] not in ['init', 'installing', 'active', 'failed', 'none']:
                msg = "os_status is not valid."
                raise HTTPNotFound(msg)
            if host_meta['os_status'] == 'init':
                if orig_host_meta.get('interfaces', None):
                    macs = [interface['mac'] for interface in orig_host_meta['interfaces']]
                    for mac in macs:
                        delete_host_discovery_info = 'pxe_os_install_clean ' + mac
                        subprocess.call(delete_host_discovery_info,
                                        shell=True,
                                        stdout=open('/dev/null', 'w'),
                                        stderr=subprocess.STDOUT)
                if (not host_meta.has_key('role') and 
                    orig_host_meta.has_key('status') and
                    orig_host_meta['status'] == 'with-role'):
                    host_meta['role'] = []
            
        if ((host_meta.has_key('ipmi_addr') and host_meta['ipmi_addr']) 
            or orig_host_meta['ipmi_addr']):
            if not host_meta.has_key('ipmi_user') and not orig_host_meta['ipmi_user']:
                host_meta['ipmi_user'] = 'zteroot'
            if not host_meta.has_key('ipmi_passwd') and not orig_host_meta['ipmi_passwd']:
                host_meta['ipmi_passwd'] = 'superuser'

        try:
            host_meta = registry.update_host_metadata(req.context,
                                                      id,
                                                      host_meta)

        except exception.Invalid as e:
            msg = (_("Failed to update host metadata. Got error: %s") %
                   utils.exception_to_str(e))
            LOG.warn(msg)
            raise HTTPBadRequest(explanation=msg,
                                 request=req,
                                 content_type="text/plain")
        except exception.NotFound as e:
            msg = (_("Failed to find host to update: %s") %
                   utils.exception_to_str(e))
            LOG.warn(msg)
            raise HTTPNotFound(explanation=msg,
                               request=req,
                               content_type="text/plain")
        except exception.Forbidden as e:
            msg = (_("Forbidden to update host: %s") %
                   utils.exception_to_str(e))
            LOG.warn(msg)
            raise HTTPForbidden(explanation=msg,
                                request=req,
                                content_type="text/plain")
        except (exception.Conflict, exception.Duplicate) as e:
            LOG.warn(utils.exception_to_str(e))
            raise HTTPConflict(body=_('Host operation conflicts'),
                               request=req,
                               content_type='text/plain')
        else:
            self.notifier.info('host.update', host_meta)

        return {'host_meta': host_meta}

class HostDeserializer(wsgi.JSONRequestDeserializer):
    """Handles deserialization of specific controller method requests."""

    def _deserialize(self, request):
        result = {}
        result["host_meta"] = utils.get_host_meta(request)
        return result

    def add_host(self, request):
        return self._deserialize(request)

    def update_host(self, request):
        return self._deserialize(request)

class HostSerializer(wsgi.JSONResponseSerializer):
    """Handles serialization of specific controller method responses."""

    def __init__(self):
        self.notifier = notifier.Notifier()

    def add_host(self, response, result):
        host_meta = result['host_meta']
        response.status = 201
        response.headers['Content-Type'] = 'application/json'
        response.body = self.to_json(dict(host=host_meta))
        return response

    def delete_host(self, response, result):
        host_meta = result['host_meta']
        response.status = 201
        response.headers['Content-Type'] = 'application/json'
        response.body = self.to_json(dict(host=host_meta))
        return response

    def get_host(self, response, result):
        host_meta = result['host_meta']
        response.status = 201
        response.headers['Content-Type'] = 'application/json'
        response.body = self.to_json(dict(host=host_meta))
        return response

def create_resource():
    """Hosts resource factory method"""
    deserializer = HostDeserializer()
    serializer = HostSerializer()
    return wsgi.Resource(Controller(), deserializer, serializer)

