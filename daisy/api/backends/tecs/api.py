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
/install endpoint for tecs API
"""
import os
import copy
import subprocess
import time
import commands

import traceback
import webob.exc
from oslo_config import cfg
from oslo_log import log as logging
from webob.exc import HTTPBadRequest
from webob.exc import HTTPForbidden
from webob.exc import HTTPServerError

import threading
from threading import Thread

from daisy import i18n
from daisy import notifier

from daisy.api import policy
import daisy.api.v1

from daisy.common import exception
import daisy.registry.client.v1.api as registry
from daisy.api.backends.tecs import config
from daisy.api.backends import driver
from daisy.api.network_api import network as neutron
from ironicclient import client as ironic_client
import daisy.api.backends.os as os_handle
import daisy.api.backends.common as daisy_cmn
import daisy.api.backends.tecs.common as tecs_cmn
import daisy.api.backends.tecs.install as instl
import daisy.api.backends.tecs.uninstall as unstl
import daisy.api.backends.tecs.upgrade as upgrd


try:
    import simplejson as json
except ImportError:
    import json

LOG = logging.getLogger(__name__)
_ = i18n._
_LE = i18n._LE
_LI = i18n._LI
_LW = i18n._LW

tecs_state = tecs_cmn.TECS_STATE

class API(driver.DeploymentDriver):
    """
    The hosts API is a RESTful web service for host data. The API
    is as follows::

        GET  /hosts -- Returns a set of brief metadata about hosts
        GET  /hosts/detail -- Returns a set of detailed metadata about
                              hosts
        HEAD /hosts/<ID> -- Return metadata about an host with id <ID>
        GET  /hosts/<ID> -- Return host data for host with id <ID>
        POST /hosts -- Store host data and return metadata about the
                        newly-stored host
        PUT  /hosts/<ID> -- Update host metadata and/or upload host
                            data for a previously-reserved host
        DELETE /hosts/<ID> -- Delete the host with id <ID>
    """

    def __init__(self):
        super(API, self).__init__()
        return

    def install(self, req, cluster_id):
        """
        Install TECS to a cluster.

        param req: The WSGI/Webob Request object
        cluster_id:cluster id
        """

        tecs_install_task = instl.TECSInstallTask(req, cluster_id)
        tecs_install_task.start()

    def _get_roles_and_hosts_ip_list(self, req, cluster_id):
        host_ha_list = set()
        host_ip_list = set()
        role_id_list = set()
        hosts_id_list = []
        hosts_list = []

        roles = daisy_cmn.get_cluster_roles_detail(req,cluster_id)
        cluster_networks = daisy_cmn.get_cluster_networks_detail(req, cluster_id)
        for role in roles:
            if role['deployment_backend'] != daisy_cmn.tecs_backend_name:
                continue
            role_hosts = daisy_cmn.get_hosts_of_role(req, role['id'])
            if role_hosts:
                for role_host in role_hosts:
                    host = daisy_cmn.get_host_detail(req, role_host['host_id'])
                    host_ip = tecs_cmn.get_mngt_network_ip(host, cluster_networks)
                    if role['name'] == "CONTROLLER_HA":
                        host_ha_list.add(host_ip)
                    host_ip_list.add(host_ip)
                    hosts_id_list.append({host['id']:host_ip})
                role_id_list.add(role['id'])
        for host in hosts_id_list:
            if host not in hosts_list:
                hosts_list.append(host)
        return (role_id_list, host_ip_list, host_ha_list, hosts_list)

    def _query_progress(self, req, cluster_id, action=""):
        nodes_list = []
        roles = daisy_cmn.get_roles_detail(req)
        (role_id_list,host_ip_list,host_ha_list,hosts_list) = self._get_roles_and_hosts_ip_list(req, cluster_id)
        for host in hosts_list:
            node = {}
            host_id = host.keys()[0]
            host = daisy_cmn.get_host_detail(req, host_id)
            node['id'] = host['id']
            node['name'] = host['name']

            if 0 == cmp("upgrade", action):
                node['os-progress'] = host['os_progress']
                node['os-status'] = host['os_status']
                node['os-messages'] = host['messages']

            if host['status'] == "with-role":
                host_roles = [ role for role in roles if role['name'] in host['role'] and role['cluster_id'] == cluster_id]
                if host_roles:
                    node['role-status'] = host_roles[0]['status']
                    node['role-progress'] = str(host_roles[0]['progress'])
                    # node['role-message'] = host_roles[0]['messages']
            nodes_list.append(node)
        return {'tecs_nodes': nodes_list}

    def uninstall(self, req, cluster_id):
        """
        Uninstall TECS to a cluster.

        :param req: The WSGI/Webob Request object

        :raises HTTPBadRequest if x-install-cluster is missing
        """

        (role_id_list, host_ip_list,host_ha_list, hosts_list) = self._get_roles_and_hosts_ip_list(req, cluster_id)
        if role_id_list:
            if not host_ip_list:
                msg = _("there is no host in cluster %s") % cluster_id
                raise exception.ThreadBinException(msg)
                
            unstl.update_progress_to_db(req, role_id_list, tecs_state['UNINSTALLING'], hosts_list, 0.0)
            uninstall_progress_percentage = round(1*1.0/len(host_ip_list), 2)*100
 
            threads = []
            for host_ip in host_ip_list:
                t = threading.Thread(target=unstl.thread_bin,args=(req,host_ip,role_id_list,uninstall_progress_percentage))
                t.setDaemon(True)
                t.start()
                threads.append(t)
            LOG.info(_("uninstall threads have started, please waiting...."))

            try:
                for t in threads:
                    t.join()
            except:
                LOG.warn(_("Join uninstall thread %s failed!" % t))
            else:
                uninstall_failed_flag = False
                for role_id in role_id_list:
                    role = daisy_cmn.get_role_detail(req, role_id)
                    # if progress is 100, it means some thing is not ready when uninstalling
                    # here can't use status ==uninstalling or progress==0 
                    if role['progress'] == 100:
                        unstl.update_progress_to_db(req, role_id_list, tecs_state['UNINSTALL_FAILED'], hosts_list)
                        uninstall_failed_flag = True
                        break
                    if role['status'] == tecs_state['UNINSTALL_FAILED']:
                        uninstall_failed_flag = True
                        break
                if not uninstall_failed_flag:
                    LOG.info(_("all uninstall threads have done, set all roles status to 'init'!"))
                    unstl.update_progress_to_db(req, role_id_list, tecs_state['INIT'], hosts_list)
                    
        try:
            (status, output) = commands.getstatusoutput('rpm -e --nodeps openstack-packstack\
                        openstack-packstack-puppet openstack-puppet-modules puppet')
        except exception.Invalid as e:
            raise HTTPBadRequest(explanation=e.msg, request=req)

    def uninstall_progress(self, req, cluster_id):
        return self._query_progress(req, cluster_id, "uninstall")

    def upgrade(self, req, cluster_id):
        """
        update TECS to a cluster.

        :param req: The WSGI/Webob Request object

        :raises HTTPBadRequest if x-install-cluster is missing
        """
        (role_id_list,host_ip_list,host_ha_list,hosts_list) = self._get_roles_and_hosts_ip_list(req, cluster_id)
        if role_id_list:
            if not host_ip_list:
                msg = _("there is no host in cluster %s") % cluster_id
                raise exception.ThreadBinException(msg)
            unreached_hosts = daisy_cmn.check_ping_hosts(host_ip_list, 1)
            if unreached_hosts:
                self.message = "hosts %s ping failed" % unreached_hosts
                raise exception.NotFound(message=self.message)
                
            daisy_cmn.subprocess_call('rm -rf /root/.ssh/known_hosts')
            
            if os_handle.check_tfg_exist():
                os_handle.upgrade_os(req, hosts_list)
                unreached_hosts = daisy_cmn.check_ping_hosts(host_ip_list, 30)
                if unreached_hosts:
                    self.message = "hosts %s ping failed after tfg upgrade" % unreached_hosts
                    raise exception.NotFound(message=self.message)
            upgrd.update_progress_to_db(req, role_id_list, tecs_state['UPDATING'], 0.0)
            update_progress_percentage = round(1*1.0/len(host_ip_list), 2)*100
            threads = []
            LOG.info(_("begin to update TECS controller nodes, please waiting...."))
            for host_ip in host_ha_list:
                LOG.info(_("update TECS controller node %s..." % host_ip))
                upgrd.thread_bin(req,host_ip,role_id_list,update_progress_percentage)
            LOG.info(_("begin to update TECS other nodes, please waiting...."))
            for host_ip in (host_ip_list - host_ha_list):
                t = threading.Thread(target=upgrd.thread_bin,args=(req,host_ip,role_id_list,update_progress_percentage))
                t.setDaemon(True)
                t.start()
                threads.append(t)
            try:
                for t in threads:
                    t.join()
            except:
                LOG.warn(_("Join update thread %s failed!" % t))
            else:
                update_failed_flag = False
                for role_id in role_id_list:
                    role = registry.get_role_metadata(req.context, role_id)
                    # if progress is 0, it means some thing is not ready when updating
                    # here can't use status ==updating or progress==100 
                    if role['progress'] == 0:
                        upgrd.update_progress_to_db(req, role_id_list, tecs_state['UPDATE_FAILED'])
                        update_failed_flag = True
                        break
                    if role['status'] == tecs_state['UPDATE_FAILED']:
                        update_failed_flag = True
                        break
                if not update_failed_flag:
                    LOG.info(_("all update threads have done, set all roles status to 'active'!"))
                    upgrd.update_progress_to_db(req, role_id_list, tecs_state['ACTIVE'])

    def upgrade_progress(self, req, cluster_id):
        return self._query_progress(req, cluster_id, "upgrade")
        

    def export_db(self, req, cluster_id):
        """
        Export daisy db data to tecs.conf and HA.conf.

        :param req: The WSGI/Webob Request object

        :raises HTTPBadRequest if x-install-cluster is missing
        """

        (tecs_config, mgnt_ip_list) = instl.get_cluster_tecs_config(req, cluster_id)

        config_files = {'tecs_conf':'','ha_conf':''}
        tecs_install_path = "/home/tecs_install"
        tecs_config_file = ''
        if tecs_config:
            cluster_conf_path = tecs_install_path + "/" + cluster_id
            create_cluster_conf_path = "rm -rf %s; mkdir %s" % (cluster_conf_path, cluster_conf_path)
            daisy_cmn.subprocess_call(create_cluster_conf_path)
            config.update_tecs_conf(tecs_config, cluster_conf_path)

            get_tecs_conf = "ls %s|grep tecs.conf" % cluster_conf_path
            obj = subprocess.Popen(get_tecs_conf, shell=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
            (stdoutput, erroutput) = obj.communicate()
            tecs_conf_file = ""
            if stdoutput:
                tecs_conf_file = stdoutput.split('\n')[0]
                config_files['tecs_conf'] = cluster_conf_path + "/" + tecs_conf_file

            get_ha_conf_cmd = "ls %s|grep HA_1.conf" % cluster_conf_path
            obj = subprocess.Popen(get_ha_conf_cmd, shell=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
            (stdoutput, erroutput) = obj.communicate()
            ha_conf_file = ""
            if stdoutput:
                ha_conf_file = stdoutput.split('\n')[0]
                config_files['ha_conf'] = cluster_conf_path + "/" + ha_conf_file
        return config_files
