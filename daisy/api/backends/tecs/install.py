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

import traceback
import webob.exc
from oslo_config import cfg
from oslo_log import log as logging
from webob.exc import HTTPBadRequest
from webob.exc import HTTPForbidden
from webob.exc import HTTPServerError

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
SUPPORTED_PARAMS = daisy.api.v1.SUPPORTED_PARAMS
SUPPORTED_FILTERS = daisy.api.v1.SUPPORTED_FILTERS
ACTIVE_IMMUTABLE = daisy.api.v1.ACTIVE_IMMUTABLE

CONF = cfg.CONF
install_opts = [
    cfg.StrOpt('max_parallel_os_number', default=10,
               help='Maximum number of hosts install os at the same time.'),
]
CONF.register_opts(install_opts)

CONF.import_opt('disk_formats', 'daisy.common.config', group='image_format')
CONF.import_opt('container_formats', 'daisy.common.config',
                group='image_format')
CONF.import_opt('image_property_quota', 'daisy.common.config')


tecs_state = tecs_cmn.TECS_STATE
daisy_tecs_path = tecs_cmn.daisy_tecs_path



def _get_host_private_networks(host_detail, cluster_private_networks_name):
    """
    User member nic pci segment replace the bond pci, we use it generate the mappings.json.
    :param host_detail: host infos
    :param cluster_private_networks_name: network info in cluster
    :return:
    """
    host_private_networks = [hi for pn in cluster_private_networks_name
                             for hi in host_detail['interfaces'] if pn in hi['assigned_networks']]

    # If port type is bond,use pci segment of member port replace pci1 & pci2 segments of bond port
    for interface_outer in host_private_networks:
        if 0 != cmp(interface_outer.get('type', None), "bond"):
            continue
        slave1 = interface_outer.get('slave1', None)
        slave2 = interface_outer.get('slave2', None)
        if not slave1 or not slave2:
            continue
        interface_outer.pop('pci')

        for interface_inner in host_detail['interfaces']:
            if 0 == cmp(interface_inner.get('name', None), slave1):
                interface_outer['pci1'] = interface_inner['pci']
            elif 0 == cmp(interface_inner.get('name', None), slave2):
                interface_outer['pci2'] = interface_inner['pci']
    return host_private_networks

def _write_private_network_cfg_to_json(private_networks):
    """
    Generate cluster private network json. We use the json file after tecs is installed.
    :param private_networks: cluster private network params set.
    :return:
    """
    if not private_networks:
        LOG.error("private networks can't be empty!")
        return False

    cluster_hosts_network_cfg = {}
    hosts_network_cfg = {}
    for k in private_networks.keys():
        private_network_info = {}
        for private_network in private_networks[k]:
            # host_interface
            type = private_network.get('type', None)
            name = private_network.get('name', None)
            assign_networks = private_network.get('assigned_networks', None)
            slave1 =  private_network.get('slave1', None)
            slave2 =  private_network.get('slave2', None)
            pci = private_network.get('pci', None)
            pci1 = private_network.get('pci1', None)
            pci2 = private_network.get('pci2', None)
            mode = private_network.get('mode', None)
            if not type or not name or not assign_networks:
                LOG.error("host_interface params invalid in private networks!")
                continue

            for assign_network in assign_networks:
                # network
                #network_type = assign_network.get('network_type', None)
                ml2_type = assign_network.get('ml2_type', None)
                physnet_name = assign_network.get('name', None)
                mtu = assign_network.get('mtu', None)
                if not ml2_type or not physnet_name:
                    LOG.error("private networks ml2_type or physnet name is invalid!")
                    continue

                physnet_name_conf = {}
                physnet_name_conf['type'] = type
                physnet_name_conf['name'] = name
                physnet_name_conf['ml2'] = ml2_type
                if mtu:
                    physnet_name_conf['mtu'] = mtu
                # physnet_name_conf['ml2'] = ml2_type + "(direct)"
                if 0 == cmp("bond", type):
                    if not pci1 or not pci2 or not slave1 or not slave2 or not mode:
                        LOG.error("when type is 'bond',input params is invalid in private networks!")
                        continue
                    physnet_name_conf['slave1'] = slave1
                    physnet_name_conf['slave2'] = slave2
                    physnet_name_conf['pci1'] = pci1
                    physnet_name_conf['pci2'] = pci2
                    physnet_name_conf['mode'] = mode
                elif 0 == cmp("ether", type):
                    if not pci:
                        LOG.error("when type is 'ether',input params is invalid in private networks!")
                        continue
                    physnet_name_conf['pci'] = pci

                if not physnet_name_conf:
                    continue
                private_network_info[physnet_name] =  physnet_name_conf

        if not private_network_info:
            continue
        hosts_network_cfg[k] = private_network_info

    if not hosts_network_cfg:
        return False
    cluster_hosts_network_cfg['hosts'] = hosts_network_cfg

    with open("/var/lib/daisy/tecs/mappings.json", "w+") as fp:
        fp.write(json.dumps(cluster_hosts_network_cfg))
    return True

def _conf_private_network(host_private_networks_dict, cluster_private_network_dict):
    if not host_private_networks_dict:
        LOG.info(_("No private network need config"))
        return {}

    # different host(with ip) in host_private_networks_dict
    config_neutron_ml2_vlan_ranges = []
    for k in host_private_networks_dict.keys():
        host_private_networks = host_private_networks_dict[k]
        # different private network plane in host_interface
        for host_private_network in host_private_networks:
            private_networks_name = host_private_network.get('assigned_networks', None)
            if not private_networks_name:
                break
            private_network_info = \
                [network for name in private_networks_name
                 for network in cluster_private_network_dict if name == network['name']]
            host_private_network['assigned_networks'] = private_network_info
            config_neutron_ml2_vlan_ranges += \
                ["%(name)s:%(vlan_start)s:%(vlan_end)s" %
                {'name':network['name'], 'vlan_start':network['vlan_start'], 'vlan_end':network['vlan_end']}
                 for network in private_network_info
                 if network['name'] and network['vlan_start'] and network['vlan_end']]

    physic_network_cfg = {}
    if _write_private_network_cfg_to_json(host_private_networks_dict):
        physic_network_cfg['json_path'] = daisy_tecs_path + "mappings.json"
    if config_neutron_ml2_vlan_ranges:
        host_private_networks_vlan_range = ",".join(list(set(config_neutron_ml2_vlan_ranges)))
        physic_network_cfg['vlan_ranges'] = host_private_networks_vlan_range
    return physic_network_cfg

def _get_host_interfaces(host_detail):
    host_mngt_network = tecs_cmn.get_mngt_interfaces(host_detail)
    has_interfaces = {'management':host_mngt_network}

    host_deploy_network = [hi for hi in host_detail['interfaces'] if 'DEPLOYMENT' in hi['assigned_networks']]
    #note:"is_deployment" can't label delpoyment network, it only used to label dhcp mac
    if host_deploy_network:
        has_interfaces.update({'deployment':host_deploy_network[0]})

    host_storage_network = [hi for hi in host_detail['interfaces'] if 'STORAGE' in hi['assigned_networks']]
    if host_storage_network:
        has_interfaces.update({'storage':host_storage_network[0]})

    return has_interfaces

def _get_host_nic_name(cluster_network, host_detail):
    """
    Different networking will generate different ha port name, the rule of generation
    is describe in comment.
    :param cluster_network: Network info in cluster.
    :param host_detail:
    :return:
    """
    copy_host_detail = copy.deepcopy(host_detail)
    if not cluster_network or not copy_host_detail:
        LOG.error("<<<FUN:change_host_nic_name_by_networking, input params invalid!>>>")
        return ""

    mgr_interface_info = tecs_cmn.get_mngt_interfaces(copy_host_detail)
    nic_info = [network
                for network in cluster_network
                for netname in mgr_interface_info.get('assigned_networks', None)
                if network.get('name', None) == netname]

    nic_capability = [info['capability'] for info in nic_info if info['network_type'] != "PRIVATE"]
    if not nic_capability:
        return ""

    mgr_nic_info = [mgr_net for mgr_net in nic_info if mgr_net['network_type'] == "MANAGEMENT"][0]
    # if private and management plane is unifier
    if set(["PRIVATE", "MANAGEMENT"]).issubset(set([info['network_type'] for info in nic_info])):
        # if type = 'ether' and  'ovs' not in ml2  and management is 'high'
        if "ether" == mgr_interface_info.get('type', None) and \
           "ovs" not in [info['ml2_type'] for info in nic_info
                          if "PRIVATE" == info['network_type']] and \
           "high" == mgr_nic_info['capability']:
            return ""

        # if ip at outer
        if mgr_interface_info.get('ip', None) and mgr_interface_info.get('name', None):
            return "v_" + mgr_interface_info['name']
        # ip at inner
        elif mgr_nic_info.get('ip', None):
            return "managent"

    if "low" not in nic_capability:
        return ""

    # if ip at outer
    if mgr_interface_info.get('ip', None) and mgr_interface_info.get('name', None):
         return "v_" + mgr_interface_info['name']

    # ip at inner
    elif mgr_nic_info.get('ip', None):
        return "managent"

def get_cluster_tecs_config(req, cluster_id):
    LOG.info(_("get tecs config from database..."))
    params = dict(limit=1000000)
    roles = daisy_cmn.get_cluster_roles_detail(req,cluster_id)
    cluster_networks = daisy_cmn.get_cluster_networks_detail(req, cluster_id)
    try:
        all_services = registry.get_services_detail(req.context, **params)
        all_components = registry.get_components_detail(req.context, **params)
        cluster_data = registry.get_cluster_metadata(req.context, cluster_id)
    except exception.Invalid as e:
        raise HTTPBadRequest(explanation=e.msg, request=req)
    
    cluster_private_network_dict = [network for network in cluster_networks if network['network_type'] == 'PRIVATE']
    cluster_private_networks_name = [network['name'] for network in cluster_private_network_dict]

    tecs_config = {}
    tecs_config.update({'OTHER':{}})
    other_config = tecs_config['OTHER']
    other_config.update({'cluster_data':cluster_data})
    tecs_installed_hosts = set()
    host_private_networks_dict = {}
    mgnt_ip_list = set()

    for role in roles:
        if role['deployment_backend'] != daisy_cmn.tecs_backend_name:
            continue
        try:
            role_service_ids = registry.get_role_services(req.context, role['id'])
        except exception.Invalid as e:
            raise HTTPBadRequest(explanation=e.msg, request=req)

        role_services_detail = [asc for rsci in role_service_ids for asc in all_services if asc['id'] == rsci['service_id']]
        component_id_to_name = dict([(ac['id'], ac['name'])  for ac in all_components])
        service_components = dict([(scd['name'], component_id_to_name[scd['component_id']]) for scd in role_services_detail])

        role_hosts = daisy_cmn.get_hosts_of_role(req, role['id'])

        host_interfaces = []
        for role_host in role_hosts:
            host_detail = daisy_cmn.get_host_detail(req, role_host['host_id'])

            sorted_host_detail = tecs_cmn.sort_interfaces_by_pci(host_detail)
            host_private_networks_list = _get_host_private_networks(sorted_host_detail,
                                                                    cluster_private_networks_name)
            # get ha nic port name
            if not other_config.has_key('ha_nic_name') and \
                role['name'] == "CONTROLLER_HA":
                mgr_nic_name = _get_host_nic_name(cluster_networks, sorted_host_detail)
                other_config.update({'ha_nic_name':mgr_nic_name})

            # mangement network must be configed
            host_mgnt_ip = tecs_cmn.get_mngt_network_ip(host_detail, cluster_networks)
            mgnt_ip_list.add(host_mgnt_ip)

            # host_mgnt_ip used to label who the private networks is
            host_private_networks_dict[host_mgnt_ip] = host_private_networks_list

            #get host ip of tecs is active
            if (role_host['status'] == tecs_state['ACTIVE'] or
                role_host['status'] == tecs_state['UPDATING'] or
                role_host['status'] == tecs_state['UPDATE_FAILED']):
                tecs_installed_hosts.add(host_mgnt_ip)
                if role['vip']:
                    tecs_installed_hosts.add(role['vip'])
            has_interfaces = _get_host_interfaces(host_detail)
            host_interfaces.append(has_interfaces)
        if host_interfaces:
            tecs_config.update({role['name']:{'services':service_components,
                                              'vip':role['vip'],
                                              'host_interfaces':host_interfaces}})
    other_config.update({'tecs_installed_hosts':tecs_installed_hosts})
    # replace private network
    physic_network_cfg = _conf_private_network(host_private_networks_dict, cluster_private_network_dict)
    other_config.update({'physic_network_config':physic_network_cfg})
    return (tecs_config, mgnt_ip_list)


class TECSInstallTask(Thread):
    """
    Class for install tecs bin.
    """
    """ Definition for install states."""

    def __init__(self, req, cluster_id):
        super(TECSInstallTask, self).__init__()
        self.req = req
        self.cluster_id = cluster_id
        self.progress = 0
        self.state = tecs_state['INIT']
        self.message = ""
        self.tecs_config_file = ''
        self.mgnt_ip_list = ''
        self.install_log_fp = None
        self.last_line_num = 0
        self.need_install = False
        self.ping_times = 36
        self.log_file = "/var/log/daisy/tecs_%s_install.log" % self.cluster_id

    def _check_install_log(self, tell_pos):
        with open(self.log_file, "r") as tmp_fp:
            tmp_fp.seek(tell_pos, os.SEEK_SET)
            line_num = self.last_line_num
            for lnum, lcontent in enumerate(tmp_fp, 1):
                tell_pos = tmp_fp.tell()
                line_num += 1
                LOG.debug("<<<Line,%s:Content,%s>>>", line_num, lcontent)
                if -1 != lcontent.find("Preparing servers"):
                    self.progress = 3

                if -1 != lcontent.find("successfully"):
                    self.progress = 100
                elif -1 != lcontent.find("Error") \
                    or -1 != lcontent.find("ERROR") \
                    or -1 != lcontent.find("error") \
                    or -1 != lcontent.find("not found"):
                    self.state = tecs_state['INSTALL_FAILED']
                    self.message = "Tecs install error, see line %s in '%s'" % (line_num,self.log_file)
                    raise exception.InstallException(
                        cluster_id=self.cluster_id, reason=self.message)
        self.last_line_num = line_num
        return tell_pos

    def _calc_progress(self, path):
        """
        Calculate the progress of installing bin.
        :param path: directory contain ".pp" and ".log" files
        :return: installing progress(between 1~100)
        """
        ppcount = logcount = 0
        for file in os.listdir(path):
            if file.endswith(".log"):
                logcount += 1
            elif file.endswith(".pp"):
                ppcount += 1

        progress = 0
        if 0 != ppcount:
            progress = (logcount * 100.00)/ ppcount
        return progress

    def _update_install_progress_to_db(self):
        """
        Update progress of intallation to db.
        :return:
        """
        roles = daisy_cmn.get_cluster_roles_detail(self.req,self.cluster_id)
        for role in roles:
            if role['deployment_backend'] != daisy_cmn.tecs_backend_name:
                continue
            role_hosts = daisy_cmn.get_hosts_of_role(self.req, role['id'])
            for role_host in role_hosts:
                if role_host['status'] != tecs_state['ACTIVE']:
                    self.need_install = True
                    role_host['status'] = self.state
                    role_host['progress'] = self.progress
                    daisy_cmn.update_role_host(self.req, role_host['id'], role_host)
                    role['progress'] = self.progress
                    role['status'] = self.state
                    role['messages'] = self.message
                    daisy_cmn.update_role(self.req, role['id'], role)
                
    def _generate_tecs_config_file(self, cluster_id, tecs_config):
        tecs_config_file = ''
        if tecs_config:
            cluster_conf_path = daisy_tecs_path + cluster_id
            LOG.info(_("generate tecs config..."))
            config.update_tecs_conf(tecs_config, cluster_conf_path)
            tecs_config_file = cluster_conf_path + "/tecs.conf"
            ha_config_file = cluster_conf_path + "/HA_1.conf"
            mkdir_tecs_install = "mkdir -p /home/tecs_install/"
            daisy_cmn.subprocess_call(mkdir_tecs_install)
            cp_ha_conf = "\cp %s /home/tecs_install/" % ha_config_file
            daisy_cmn.subprocess_call(cp_ha_conf)
        return tecs_config_file

    def run(self):
        try:
            self._run()
        except (exception.InstallException,
                exception.NotFound,
                exception.InstallTimeoutException) as e:
            LOG.exception(e.message)
        else:
            if not self.need_install:
                return
            self.progress = 100
            self.state = tecs_state['ACTIVE']
            self.message = "Tecs install successfully"
            LOG.info(_("install TECS for cluster %s successfully."
                        % self.cluster_id))

            # load neutron conf after installation
            result = config.get_conf(self.tecs_config_file,
                            neutron_float_ip="CONFIG_NEUTRON_SERVER_HOST",
                            keystone_float_ip="CONFIG_KEYSTONE_HOST",
                            neutron_install_mode="CONFIG_NEUTRON_SERVER_INSTALL_MODE",
                            keystone_install_mode="CONFIG_KEYSTONE_INSTALL_MODE",
                            lb_float_ip="CONFIG_LB_HOST")
            if (result.get('keystone_install_mode', None) == "LB" and
                    result.get('neutron_install_mode', None) == "LB"):
                LOG.info(_("<<<begin config lb neutron.>>>"))
                time.sleep(20)
                neutron(self.req,
                        result.get('lb_float_ip', None),
                        result.get('lb_float_ip', None),
                        self.cluster_id)
            else:
                LOG.info(_("<<<begin config neutron.>>>"))
                time.sleep(20)
                neutron(self.req,
                        result.get('neutron_float_ip', None),
                        result.get('keystone_float_ip', None),
                        self.cluster_id)
        finally:
            self._update_install_progress_to_db()
            if self.install_log_fp:
                self.install_log_fp.close()

    def _run(self):
        """
        Exectue install file(.bin) with sync mode.
        :return:
        """
        def check_and_get_tecs_version(daisy_tecs_pkg_path):
            tecs_version_pkg_file = ""
            get_tecs_version_pkg = "ls %s| grep ^ZXTECS.*\.bin$" % daisy_tecs_pkg_path
            obj = subprocess.Popen(get_tecs_version_pkg,
                                shell=True,
                                stdout=subprocess.PIPE,
                                stderr=subprocess.PIPE)
            (stdoutput, erroutput) = obj.communicate()
            if stdoutput:
                tecs_version_pkg_name = stdoutput.split('\n')[0]
                tecs_version_pkg_file = daisy_tecs_pkg_path + tecs_version_pkg_name
                chmod_for_tecs_version = 'chmod +x %s' % tecs_version_pkg_file
                daisy_cmn.subprocess_call(chmod_for_tecs_version)
            return tecs_version_pkg_file

        def executor(**params):
            # if subprocsee is failed, we need break
            if os.path.exists(self.log_file):
                params['tell_pos'] =  self._check_install_log(params.get('tell_pos', 0))
                LOG.debug(_("<<<Check install bin is OK.>>>"))
                if 100 == self.progress:
                    return params
                if 3 == self.progress:
                    self._update_install_progress_to_db()
            # waiting for 'progress_log_location' file exist
            if not params.get("if_progress_file_read", None):
                if not os.path.exists(self.progress_log_location):
                    params['if_progress_file_read'] = False
                    return params
                else:
                    with open(self.progress_log_location, "r") as fp:
                        line = fp.readline()
                        self.progress_logs_path = line.split('\n')[0] + "/manifests"
                        params['if_progress_file_read'] = True

            # waiting for 'self.progress_logs_path' file exist
            if not os.path.exists(self.progress_logs_path):
                return params

            LOG.debug(_("<<<Calc install progress.>>>"))

            # cacl progress & sync to db
            progress = self._calc_progress(self.progress_logs_path)

            if self.progress != progress and progress >= 3:
                self.progress = progress
                self.state = tecs_state['INSTALLING']
                self._update_install_progress_to_db()
            elif progress == 100:
                self.progress = 100
                self.state = tecs_state['ACTIVE']
                self.message = "Tecs install successfully"
            return params

        if not self.cluster_id or \
            not self.req:
            raise exception.InstallException(
                cluster_id=self.cluster_id, reason="invalid params.")

        (tecs_config, self.mgnt_ip_list) = get_cluster_tecs_config(self.req, self.cluster_id)
        # after os is installed successfully, if ping all role hosts
        # management ip successfully, begin to install TECS
        unreached_hosts = daisy_cmn.check_ping_hosts(self.mgnt_ip_list, self.ping_times)
        if unreached_hosts:
            self.state = tecs_state['INSTALL_FAILED']
            self.message = "hosts %s ping failed" % unreached_hosts
            raise exception.NotFound(message=self.message)
        # generate tecs config must be after ping check
        self.tecs_config_file = self._generate_tecs_config_file(self.cluster_id,
                                                                tecs_config)

        # install network-configuration-1.1.1-15.x86_64.rpm
        if self.mgnt_ip_list:
            # modify for 611004210035
            time.sleep(5)
            for mgnt_ip in self.mgnt_ip_list:
                tecs_cmn.TecsShellExector(mgnt_ip, 'install_rpm')

        # check and get TECS version
        tecs_version_pkg_file = check_and_get_tecs_version(daisy_tecs_path)
        if not tecs_version_pkg_file:
            self.state = tecs_state['INSTALL_FAILED']
            self.message = "TECS version file not found in %s" % daisy_tecs_path
            raise exception.NotFound(message=self.message)
        # use pattern 'tecs_%s_install' to distinguish multi clusters installation
        self.install_log_fp = open(self.log_file, "w+")
        LOG.info(_("open log file for TECS installation."))

        # delete cluster_id file before installing
        self.progress_log_location = "/var/tmp/packstack/%s" % self.cluster_id
        if os.path.exists(self.progress_log_location):
            os.remove(self.progress_log_location)

        self._update_install_progress_to_db()
        if not self.need_install:
            LOG.info(_("No host in cluster %s need to install tecs."
                    % self.cluster_id))
            return

        LOG.info(_("Begin to install TECS in cluster %s." % self.cluster_id))
        install_cmd = "sudo %s conf_file %s" % (tecs_version_pkg_file, self.tecs_config_file)
        clush_bin = subprocess.Popen(
            install_cmd, shell=True, stdout=self.install_log_fp, stderr=self.install_log_fp)

        self.progress = 1
        self.state = tecs_state['INSTALLING']
        self.message = "TECS is installing"
        self._update_install_progress_to_db()
        # if clush_bin is not terminate
        # while not clush_bin.returncode:
        params = {}  # executor params
        execute_times = 0 # executor run times
        while True:
            time.sleep(5)
            if self.progress == 100:
                break
            elif execute_times >= 1440:
                self.state = tecs_state['INSTALL_FAILED']
                self.message = "TECS install timeout for 2 hours"
                raise exception.InstallTimeoutException(cluster_id=self.cluster_id)
            params = executor(
                # just read cluster_id file once in 'while'
                if_progress_file_read=params.get("if_progress_file_read", False),
                # current fp location of tecs_install.log
                tell_pos=params.get("tell_pos", 0))

            # get clush_bin.returncode
            # clush_bin.poll()
            execute_times += 1


