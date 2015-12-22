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
import copy
import subprocess
import time

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
import daisy.api.backends.common as daisy_cmn
import daisy.api.backends.tecs.common as tecs_cmn


try:
    import simplejson as json
except ImportError:
    import json

LOG = logging.getLogger(__name__)
_ = i18n._
_LE = i18n._LE
_LI = i18n._LI
_LW = i18n._LW

CONF = cfg.CONF
install_opts = [
    cfg.StrOpt('max_parallel_os_number', default=10,
               help='Maximum number of hosts install os at the same time.'),
]
CONF.register_opts(install_opts)


host_os_status = {
    'INIT' : 'init',
    'INSTALLING' : 'installing',
    'ACTIVE' : 'active',
    'INSTALL_FAILED': 'install-failed',
    'UPDATING': 'updating',
    'UPDATE_FAILED': 'update-failed'
}

daisy_tecs_path = tecs_cmn.daisy_tecs_path
 
def get_ironicclient():  # pragma: no cover
    """Get Ironic client instance."""
    args = {'os_auth_token': 'fake',
            'ironic_url':'http://127.0.0.1:6385/v1'}
    return ironic_client.get_client(1, **args)
    
def pxe_server_build(req, install_meta):
    cluster_id = install_meta['cluster_id']
    try:
        networks = registry.get_networks_detail(req.context, cluster_id)
    except exception.Invalid as e:
        raise HTTPBadRequest(explanation=e.msg, request=req)

    try:
        ip_inter = lambda x:sum([256**j*int(i) for j,i in enumerate(x.split('.')[::-1])])
        inter_ip = lambda x: '.'.join([str(x/(256**i)%256) for i in range(3,-1,-1)])
        network_cidr = [network['cidr'] for network in networks if network['name'] == 'DEPLOYMENT'][0]
        if not network_cidr:
            network_cidr="192.168.1.1/24"
        ip_tmp_cidr=network_cidr.split('/')[0]
        inter_tmp=(ip_inter(ip_tmp_cidr))+1
        pxe_server_ip=inter_ip(inter_tmp)
        cidr_end=network_cidr.split('/')[1]
        cidr_end_inter=2**32-2**(32-int(cidr_end))
        net_mask=inter_ip(cidr_end_inter)
        client_tmp_begin=(ip_inter(ip_tmp_cidr))+2
        client_ip_begin=inter_ip(client_tmp_begin)
        cidr_max_inter=inter_tmp+(2**(32-int(cidr_end)))-4
        client_ip_end=inter_ip(cidr_max_inter)
        args = {'build_pxe': 'yes', 'eth_name': install_meta['deployment_interface'], 'ip_address': pxe_server_ip, 'net_mask': net_mask,
                'client_ip_begin': client_ip_begin, 'client_ip_end': client_ip_end}
        ironic = get_ironicclient()
        ironic.daisy.build_pxe(**args)
    except exception.Invalid as e:
        msg = "build pxe server failed"
        raise exception.InvalidNetworkConfig(msg)

def _get_network_plat(host_config, cluster_networks, dhcp_mac):
    host_config['dhcp_mac'] = dhcp_mac
    if host_config['interfaces']:
        count = 0
        for interface in host_config['interfaces']:
            count += 1
            if (interface.has_key('assigned_networks') and
                interface['assigned_networks']):
                interface_networks = copy.deepcopy(interface['assigned_networks'])
                host_config['interfaces'][count-1]['assigned_networks'] = []
                for network_type in interface_networks:
                    cluster_network = [network for network in cluster_networks if network['name'] == network_type][0]
                    # convert cidr to netmask
                    cidr_to_ip = ""
                    if cluster_network.get('cidr', None):
                        inter_ip = lambda x: '.'.join([str(x/(256**i)%256) for i in range(3,-1,-1)])
                        cidr_to_ip = inter_ip(2**32-2**(32-int(cluster_network['cidr'].split('/')[1])))
                    network_plat = dict(network_type=cluster_network['network_type'],
                                        ml2_type=cluster_network['ml2_type'],
                                        capability=cluster_network['capability'],
                                        physnet_name=cluster_network['physnet_name'],
                                        gateway=cluster_network.get('gateway', ""),
                                        ip=cluster_network.get('ip', ""),
                                        netmask=cidr_to_ip,
                                        vlan_id=cluster_network.get('vlan_id', ""))
                    host_config['interfaces'][count-1]['assigned_networks'].append(network_plat)
    return host_config

def get_cluster_hosts_config(req, cluster_id):
    params = dict(limit=1000000)
    try:
        cluster_data = registry.get_cluster_metadata(req.context, cluster_id)
        networks = registry.get_networks_detail(req.context, cluster_id)
        all_roles = registry.get_roles_detail(req.context)
    except exception.Invalid as e:
        raise HTTPBadRequest(explanation=e.msg, request=req)

    roles = [role for role in all_roles if role['cluster_id'] == cluster_id]
    all_hosts_ids = cluster_data['nodes']
    hosts_config = []
    for host_id in all_hosts_ids:
        host_detail = daisy_cmn.get_host_detail(req, host_id)
        role_host_db_lv_size_lists = list()
        if host_detail.has_key('role') and host_detail['role']:
            host_roles = host_detail['role']
            for role in roles:
                if role['name'] in host_detail['role'] and role['glance_lv_size']:
                    host_detail['glance_lv_size'] = role['glance_lv_size']
                if role.get('db_lv_size', None) and host_roles and role['name'] in host_roles:
                    role_host_db_lv_size_lists.append(role['db_lv_size'])
                if role['name'] == 'COMPUTER' and role['name'] in host_detail['role'] and role['nova_lv_size']:
                    host_detail['nova_lv_size'] = role['nova_lv_size']
            if role_host_db_lv_size_lists:
                host_detail['db_lv_size'] = max(role_host_db_lv_size_lists)
            else:
                host_detail['db_lv_size'] = 0
        if (host_detail['os_status'] == host_os_status['INIT'] or 
            host_detail['os_status'] == host_os_status['INSTALLING'] or
            host_detail['os_status'] == host_os_status['INSTALL_FAILED']):
            host_dhcp_interface = [hi for hi in host_detail['interfaces'] if hi['is_deployment']]
            if not host_dhcp_interface:
                msg = "cann't find dhcp interface on host %s" % host_detail['id']
                raise exception.InvalidNetworkConfig(msg)
            if len(host_dhcp_interface) > 1:
                msg = "dhcp interface should only has one on host %s" % host_detail['id']
                raise exception.InvalidNetworkConfig(msg)
    
            host_config_detail = copy.deepcopy(host_detail)
            host_config = _get_network_plat(host_config_detail,
                                                networks,
                                                host_dhcp_interface[0]['mac'])
            hosts_config.append(tecs_cmn.sort_interfaces_by_pci(host_config))
    return hosts_config

def check_tfg_exist():
    get_tfg_patch = "ls %s|grep ^ZXTFG-.*\.bin$" % daisy_tecs_path
    obj = subprocess.Popen(get_tfg_patch,
                           shell=True,
                           stdout=subprocess.PIPE,
                           stderr=subprocess.PIPE)
    (stdoutput, erroutput) = obj.communicate()
    tfg_patch_pkg_file = ""
    tfg_patch_pkg_name = ""
    if stdoutput:
        tfg_patch_pkg_name = stdoutput.split('\n')[0]
        tfg_patch_pkg_file = daisy_tecs_path + tfg_patch_pkg_name
        chmod_for_tfg_bin = 'chmod +x %s' % tfg_patch_pkg_file
        daisy_cmn.subprocess_call(chmod_for_tfg_bin)
        
    if not stdoutput or not tfg_patch_pkg_name:
        LOG.info(_("no ZXTFG patch bin file got in %s" % daisy_tecs_path)) 
        return ""
    return tfg_patch_pkg_file

def update_db_host_status(req, host_id, host_status):
        """
        Update host status and intallation progress to db.
        :return:
        """
        try:
            host_meta = {}
            host_meta['os_progress'] = host_status['os_progress']
            host_meta['os_status'] = host_status['os_status']
            host_meta['messages'] = host_status['messages']
            registry.update_host_metadata(req.context,
                                          host_id,
                                          host_meta)
        except exception.Invalid as e:
            raise HTTPBadRequest(explanation=e.msg, request=req)  

class OSInstall():
    """
    Class for install OS.
    """
    """ Definition for install states."""
    def __init__(self, req, cluster_id):
        self.req = req
        self.cluster_id = cluster_id
        #5s
        self.time_step = 5
        # 30 min
        self.single_host_install_timeout = 30 * (12*self.time_step)

        self.max_parallel_os_num = int(CONF.max_parallel_os_number)
        self.cluster_hosts_install_timeout = (self.max_parallel_os_num/4 + 2 )* 60 * (12*self.time_step)
        self.ironicclient = get_ironicclient()

    def _set_boot_or_power_state(self, user, passwd, addr, action):
        count = 0
        repeat_times = 24
        while count < repeat_times:
            set_obj = self.ironicclient.daisy.set_boot_or_power_state(user,
                                                            passwd,
                                                            addr,
                                                            action)
            set_dict = dict([(f, getattr(set_obj, f, '')) for f in ['return_code', 'info']])
            rc = int(set_dict['return_code'])
            if rc == 0:
                LOG.info(_("set %s to '%s' successfully for %s times by ironic" % (addr,action,count+1)))
                break
            else:
                count += 1
                LOG.info(_("try setting %s to '%s' failed for %s times by ironic" % (addr,action,count)))
                time.sleep(count*2)
        if count >= repeat_times:
            message = "set %s to '%s' failed for 10 mins" % (addr,action)
            raise exception.IMPIOprationFailed(message=message)

    def _baremetal_install_os(self, host_detail):
       # os_install_disk = 'sda'
        os_version_file = host_detail['os_version_file']
        if os_version_file:
            test_os_version_exist = 'test -f %s' % os_version_file
            daisy_cmn.subprocess_call(test_os_version_exist)
        else:
            self.message = "no OS version file configed for host %s" %  host_detail['id']
            raise exception.NotFound(message=self.message)

        if host_detail.get('root_disk',None):
            root_disk = host_detail['root_disk']
        else:
            root_disk = 'sda'
        if host_detail.get('root_lv_size',None):
            root_lv_size_m = host_detail['root_lv_size']
        else:
            root_lv_size_m = 51200
        memory_size_b_str = str(host_detail['memory']['total'])
        memory_size_b_int = int(memory_size_b_str.strip().split()[0])
        memory_size_m = memory_size_b_int//1024
        memory_size_g = memory_size_m//1024
        swap_lv_size_m = host_detail['swap_lv_size']
        cinder_vg_size_m = 0
        disk_list = []
        disk_storage_size_b = 0
        for key in host_detail['disks']:
            disk_list.append(host_detail['disks'][key]['name'])
            stroage_size_str = host_detail['disks'][key]['size']
            stroage_size_b_int = int(stroage_size_str.strip().split()[0])
            disk_storage_size_b = disk_storage_size_b + stroage_size_b_int
            
        disk_list = ','.join(disk_list)
        disk_storage_size_m = disk_storage_size_b//(1024*1024)      
        if host_detail.has_key('root_pwd') and host_detail['root_pwd']:
            root_pwd = host_detail['root_pwd']
        else:
            root_pwd = 'ossdbg1'
            
        tfg_patch_pkg_file = check_tfg_exist()

        if (not host_detail['ipmi_user'] or
            not host_detail['ipmi_passwd'] or
            not host_detail['ipmi_addr'] ):
            self.message = "Invalid ipmi information configed for host %s" %  host_detail['id']
            raise exception.NotFound(message=self.message)



        self._set_boot_or_power_state(host_detail['ipmi_user'],
                                      host_detail['ipmi_passwd'],
                                      host_detail['ipmi_addr'],
                                      'pxe')

        kwargs = {'hostname':host_detail['name'],
                  'iso_path':os_version_file,
                  'tfg_bin':tfg_patch_pkg_file,
                  'dhcp_mac':host_detail['dhcp_mac'],
                  'storage_size':disk_storage_size_m,
                  'memory_size':memory_size_g,
                  'interfaces':host_detail['interfaces'],
                  'root_lv_size':root_lv_size_m,
                  'swap_lv_size':swap_lv_size_m,
                  'cinder_vg_size':cinder_vg_size_m,
                  'disk_list':disk_list,
                  'root_disk':root_disk,
                  'root_pwd':root_pwd,
                  'reboot':'no'}
        
        if host_detail.has_key('glance_lv_size'):
            kwargs['glance_lv_size'] = host_detail['glance_lv_size']
        else:
            kwargs['glance_lv_size'] = 0
            
        if host_detail.has_key('db_lv_size') and host_detail['db_lv_size']:
            kwargs['db_lv_size'] = host_detail['db_lv_size']
        else:
            kwargs['db_lv_size'] = 0
        if host_detail.has_key('nova_lv_size') and host_detail['nova_lv_size']:
            kwargs['nova_lv_size'] = host_detail['nova_lv_size']
        else:
            kwargs['nova_lv_size'] = 0
        install_os_obj = self.ironicclient.daisy.install_os(**kwargs)
        install_os_dict = dict([(f, getattr(install_os_obj, f, '')) for f in ['return_code', 'info']])
        rc = int(install_os_dict['return_code'])
        if rc != 0:
            install_os_description = install_os_dict['info']
            LOG.info(_("install os config failed because of '%s'" % (install_os_description)))
            host_status = {'os_status':host_os_status['INSTALL_FAILED'],
                           'os_progress':0,
                           'messages':install_os_description}
            update_db_host_status(self.req, host_detail['id'],host_status)
            msg = "ironic install os return failed for host %s" %  host_detail['id']
            raise exception.OSInstallFailed(message=msg)

        self._set_boot_or_power_state(host_detail['ipmi_user'],
                                      host_detail['ipmi_passwd'],
                                      host_detail['ipmi_addr'],
                                      'reset')



    def _install_os_by_rousource_type(self, hosts_detail):
        # all hosts status set to 'init' before install os
        for host_detail in hosts_detail:
            host_status = {'os_status':host_os_status['INIT'],
                           'os_progress':0,
                           'messages':''}
            update_db_host_status(self.req, host_detail['id'],host_status)

        for host_detail in hosts_detail:
            self._baremetal_install_os(host_detail)


    def _set_disk_start_mode(self, host_detail):
        LOG.info(_("Set boot from disk for host %s" % (host_detail['id'])))
        self._set_boot_or_power_state(host_detail['ipmi_user'],
                                      host_detail['ipmi_passwd'],
                                      host_detail['ipmi_addr'],
                                      'disk')
        LOG.info(_("reboot host %s" % (host_detail['id'])))
        self._set_boot_or_power_state(host_detail['ipmi_user'],
                                      host_detail['ipmi_passwd'],
                                      host_detail['ipmi_addr'],
                                      'reset')

    def _init_progress(self, host_detail, hosts_status):
        host_id = host_detail['id']

        host_status = hosts_status[host_id] = {}
        host_status['os_status'] = host_os_status['INSTALLING']
        host_status['os_progress'] = 0
        host_status['count'] = 0
        if host_detail['resource_type'] == 'docker':
            host_status['messages'] = "docker container is creating"
        else:
            host_status['messages'] = "os is installing"

        update_db_host_status(self.req, host_id, host_status)

    def _query_host_progress(self, host_detail, host_status, host_last_status):
        host_id = host_detail['id']
        install_result_obj = \
            self.ironicclient.daisy.get_install_progress(host_detail['dhcp_mac'])
        install_result = dict([(f, getattr(install_result_obj, f, ''))
                                for f in ['return_code', 'info', 'progress']])
        rc = int(install_result['return_code'])
        host_status['os_progress'] = int(install_result['progress'])
        if rc == 0:
            if host_status['os_progress'] == 100:
                LOG.info(_("host %s install os completely." % host_id))
                host_status['os_status'] = host_os_status['ACTIVE']
                host_status['messages'] = "os installed successfully"
                # wait for nicfix script complete
                time.sleep(10)
                self._set_disk_start_mode(host_detail)
            else:
                if host_status['os_progress'] == host_last_status['os_progress']:
                    host_status['count'] = host_status['count'] + 1
                    LOG.debug(_("host %s has kept %ss when progress is %s." % (host_id,
                        host_status['count']*self.time_step, host_status['os_progress'])))
        else:
            LOG.info(_("host %s install failed." % host_id))
            host_status['os_status'] = host_os_status['INSTALL_FAILED']
            host_status['messages'] = install_result['info']

    def _query_progress(self, hosts_last_status, hosts_detail):
        hosts_status = copy.deepcopy(hosts_last_status)
        for host_detail in hosts_detail:
            host_id = host_detail['id']
            if not hosts_status.has_key(host_id):
                self._init_progress(host_detail, hosts_status)
                continue

            host_status = hosts_status[host_id]
            host_last_status = hosts_last_status[host_id]
            #only process installing hosts after init, other hosts info will be kept in hosts_status
            if host_status['os_status'] != host_os_status['INSTALLING']:
                continue

            self._query_host_progress(host_detail, host_status, host_last_status)

            if host_status['count']*self.time_step >= self.single_host_install_timeout:
                host_status['os_status'] = host_os_status['INSTALL_FAILED']
                if host_detail['resource_type'] == 'docker':
                    host_status['messages'] = "docker container created timeout"
                else:
                    host_status['messages'] = "os installed timeout"
            if (host_status['os_progress'] != host_last_status['os_progress'] or\
                    host_status['os_status'] != host_last_status['os_status']):
                host_status['count'] = 0
                update_db_host_status(self.req, host_id,host_status)
        return hosts_status

    def _get_install_status(self, hosts_detail):
        query_count = 0
        hosts_last_status = {}
        while True:
            hosts_install_status = self._query_progress(hosts_last_status, hosts_detail)
            # if all hosts install over, break
            installing_hosts = [id for id in hosts_install_status.keys()
                if hosts_install_status[id]['os_status'] == host_os_status['INSTALLING']]
            if not installing_hosts:
                break
            #after 3h, if some hosts are not 'active', label them to 'failed'.
            elif query_count*self.time_step >= self.cluster_hosts_install_timeout:
                for host_id,host_status in hosts_install_status.iteritems():
                    if (host_status['os_status'] != host_os_status['ACTIVE'] and
                       host_status['os_status'] != host_os_status['INSTALL_FAILED']):
                        # label the host install failed because of time out for 3h
                        host_status['os_status'] = host_os_status['INSTALL_FAILED']
                        host_status['messages'] = "cluster os installed timeout"
                        update_db_host_status(self.req, host_id, host_status)
                break
            else:
                query_count += 1
                hosts_last_status = hosts_install_status
                time.sleep(self.time_step)
        return hosts_install_status

    def install_os(self, hosts_detail, role_hosts_ids):
        if len(hosts_detail) > self.max_parallel_os_num:
            install_hosts = hosts_detail[:self.max_parallel_os_num]
            hosts_detail = hosts_detail[self.max_parallel_os_num:]
        else:
            install_hosts = hosts_detail
            hosts_detail = []
 
        install_hosts_id = [host_detail['id'] for host_detail in install_hosts]
        LOG.info(_("Begin install os for hosts %s." % ','.join(install_hosts_id)))
        self._install_os_by_rousource_type(install_hosts)
        LOG.info(_("Begin to query install progress..."))
        # wait to install completely
        cluster_install_status = self._get_install_status(install_hosts)
        LOG.info(_("OS install in cluster %s result is:" % self.cluster_id))
        LOG.info(_("%s                                %s        %s" % ('host-id', 'os-status', 'description')))
 
        for host_id,host_status in cluster_install_status.iteritems():
            LOG.info(_("%s   %s   %s" % (host_id, host_status['os_status'], host_status['messages'])))
            if host_id in role_hosts_ids:
                if host_status['os_status'] == host_os_status['INSTALL_FAILED']:
                    break
                else:
                    role_hosts_ids.remove(host_id)
        return (hosts_detail, role_hosts_ids)

        
def _os_thread_bin(req, host_ip, host_id):
    host_meta = {}
    password = "ossdbg1"
    LOG.info(_("Begin update os for host %s." % (host_ip)))
    cmd = 'mkdir -p /var/log/daisy/daisy_update/'
    daisy_cmn.subprocess_call(cmd)

    var_log_path = "/var/log/daisy/daisy_update/%s_update_tfg.log" % host_ip
    with open(var_log_path, "w+") as fp:
        cmd = '/var/lib/daisy/tecs/trustme.sh %s %s' % (host_ip, password)
        daisy_cmn.subprocess_call(cmd,fp)
        cmd = 'clush -S -b -w %s  "rm -rf /home/daisy_update"' % (host_ip,)
        daisy_cmn.subprocess_call(cmd,fp)
        cmd = 'clush -S -w %s "mkdir -p /home/daisy_update"' % (host_ip,)
        daisy_cmn.subprocess_call(cmd,fp)
        cmd = 'clush -S -w %s -c /var/lib/daisy/tecs/ZXTFG*.bin --dest=/home/daisy_update' % (host_ip,)
        daisy_cmn.subprocess_call(cmd,fp)
        cmd = 'clush -S -w %s "chmod 777 /home/daisy_update/*"' % (host_ip,)
        daisy_cmn.subprocess_call(cmd,fp)

        try:
            exc_result = subprocess.check_output(
                'clush -S -w %s "/home/daisy_update/ZXTFG*.bin upgrade reboot"' % (host_ip,),
                shell=True, stderr=subprocess.STDOUT)
        except subprocess.CalledProcessError as e:
            if e.returncode == 255 and "System will reboot" in e.output.strip():
                host_meta['os_progress'] = 100
                host_meta['os_status'] = host_os_status['ACTIVE']
                host_meta['messages'] = e.output.strip()
                LOG.info(_("Update tfg for %s successfully,os reboot!" % host_ip))
                time.sleep(20)
            else:
                host_meta['os_progress'] = 0
                host_meta['os_status'] = host_os_status['UPDATE_FAILED']
                host_meta['messages'] = e.output.strip()
                LOG.info(_("Update tfg for %s failed!" % host_ip))
            update_db_host_status(req, host_id, host_meta)            
            fp.write(e.output.strip())
        else:
            if "System will reboot" in exc_result:
                time.sleep(20)
            host_meta['os_progress'] = 100
            host_meta['os_status'] = host_os_status['ACTIVE']
            host_meta['messages'] = ""
            update_db_host_status(req, host_id, host_meta)
            LOG.info(_("Update os for %s successfully!" % host_ip))
            fp.write(exc_result)
# this will be raise raise all the exceptions of the thread to log file  
def os_thread_bin(req, host_ip, host_id):
    try:
        _os_thread_bin(req, host_ip, host_id)
    except Exception as e:
        LOG.exception(e.message)

def upgrade_os(req, hosts_list): 
    threads = []
    host_meta = {}
    for host_info in hosts_list:
        host_id = host_info.keys()[0]
        host_ip = host_info.values()[0]
        
        host_meta['os_progress'] = 1
        host_meta['os_status'] = host_os_status['UPDATING']
        host_meta['messages'] = ""
        update_db_host_status(req, host_id,host_meta)
        t = threading.Thread(target=os_thread_bin,args=(req,host_ip,host_id))
        t.setDaemon(True)
        t.start()
        threads.append(t)
    try:
        for t in threads:
            t.join()
    except:
        LOG.warn(_("Join update thread %s failed!" % t))
    else:
        for host_info in hosts_list:
            update_failed_flag = False
            host_id = host_info.keys()[0]
            host_ip = host_info.values()[0]
            host = registry.get_host_metadata(req.context, host_id)
            if host['os_status'] == host_os_status['UPDATE_FAILED'] or host['os_status'] == host_os_status['INIT']:
                update_failed_flag = True
                raise exception.ThreadBinException("%s update tfg failed! %s" % (host_ip, host['messages']))
            if not update_failed_flag:
                host_meta = {}
                host_meta['os_progress'] = 100
                host_meta['os_status'] = host_os_status['ACTIVE']
                host_meta['messages'] = ""
                update_db_host_status(req, host_id,host_meta)  
