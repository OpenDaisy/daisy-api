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

from threading import Thread

from daisy import i18n
from daisy import notifier

from daisy.api import policy
import daisy.api.v1

from daisy.common import exception
import daisy.registry.client.v1.api as registry


try:
    import simplejson as json
except ImportError:
    import json

LOG = logging.getLogger(__name__)
_ = i18n._
_LE = i18n._LE
_LI = i18n._LI
_LW = i18n._LW

daisy_tecs_path = '/var/lib/daisy/tecs/'

TECS_STATE = {
    'INIT' : 'init',
    'INSTALLING' : 'installing',
    'ACTIVE' : 'active',
    'INSTALL_FAILED': 'install-failed',
    'UNINSTALLING': 'uninstalling',
    'UNINSTALL_FAILED': 'uninstall-failed',
    'UPDATING': 'updating',
    'UPDATE_FAILED': 'update-failed',
}

def get_mngt_interfaces(host_detail):
    host_mngt_network_list = [hi for hi in host_detail['interfaces'] if 'MANAGEMENT' in hi['assigned_networks']]
    if not host_mngt_network_list:
        msg = "management network of host %s can't be empty" % host_detail['id']
        raise exception.InvalidNetworkConfig(msg)
    return host_mngt_network_list[0]
    
def get_mngt_network_ip(host_detail, cluster_networks):
    host_mngt_network = get_mngt_interfaces(host_detail)
    #add by 10166727--------start------------
    host_mgnt_ip=''
    host_mngt_ip_list=host_mngt_network['ip'].split(",")
    for host_mngt_ip in host_mngt_ip_list:
        if str('MANAGEMENT')==str(host_mngt_ip.split(':')[0]):
                host_mgnt_ip = host_mngt_ip.split(':')[1]
    #add by 10166727--------end-------------
    if not host_mgnt_ip:
        cluster_management_network = [network for network in cluster_networks if network['network_type'] == 'MANAGEMENT']
        if not cluster_management_network or not cluster_management_network[0].has_key('ip'):
            msg = "can't get management ip of host %s" % host_detail['id']
            raise exception.InvalidNetworkConfig(msg)
        else:
            host_mgnt_ip = cluster_management_network[0]['ip']
    if not host_mgnt_ip:
        msg = "management ip of host %s can't be empty" % host_detail['id']
        raise exception.InvalidNetworkConfig(msg)
    return  host_mgnt_ip

def sort_interfaces_by_pci(host_detail):
    """
    Sort interfaces by pci segment, if interface type is bond,
    user the pci of first memeber nic.This function is fix bug for
    the name length of ovs virtual port, because if the name length large than
    15 characters, the port will create failed.
    :param interfaces: interfaces info of the host
    :return:
    """
    interfaces = eval(host_detail.get('interfaces', None)) \
        if isinstance(host_detail, unicode) else host_detail.get('interfaces', None)
    if not interfaces:
        LOG.info("This host don't have interfaces info.")
        return

    tmp_interfaces = copy.deepcopy(interfaces)
    if not [interface for interface in tmp_interfaces
            if interface.get('name', None) and len(interface['name']) > 5]:
        LOG.info("The interfaces name of host is all less than 5 character, no need sort.")
        return

    # add pci segment for the bond nic, the pci is equal to the first member nic pci
    slaves_name_list = []
    for interface in tmp_interfaces:
        if interface.get('type', None) == "bond" and \
            interface.get('slave1', None) and interface.get('slave2', None):

            slaves_name_list.append(interface['slave1'])
            slaves_name_list.append(interface['slave2'])
            first_member_nic_name = interface['slave1']

            tmp_pci = [interface_tmp['pci']
                       for interface_tmp in tmp_interfaces
                       if interface_tmp.get('name', None) and
                       interface_tmp.get('pci', None) and
                       interface_tmp['name'] == first_member_nic_name]

            if len(tmp_pci) != 1:
                LOG.error("This host have two nics with same pci.")
                continue
            interface['pci'] = tmp_pci[0]

    tmp_interfaces = [interface for interface in tmp_interfaces
                      if interface.get('name', None) and
                      interface['name'] not in slaves_name_list]

    tmp_interfaces = sorted(tmp_interfaces, key = lambda interface: interface['pci'])
    for index in range(0, len(tmp_interfaces)):
        for interface in interfaces:
            if interface['name'] != tmp_interfaces[index]['name']:
                continue

            interface['name'] = "b" + str(index) if interface['type'] == "bond" else "e" + str(index)

    tmp_host_detail = copy.deepcopy(host_detail)
    tmp_host_detail.update({'interfaces': interfaces})
    return tmp_host_detail

class TecsShellExector(object):
    """
    Class config task before install tecs bin.
    """
    def __init__(self, mgnt_ip, task_type,  params={}):
        self.task_type = task_type
        self.mgnt_ip = mgnt_ip
        self.params = params
        self.clush_cmd = ""
        self.NETCFG_RPM_PATH = daisy_tecs_path + "network-configuration-1.1.1-15.x86_64.rpm"
        self.oper_type = {
            'install_rpm' : self._install_netcfg_rpm,
            'uninstall_rpm' : self._uninstall_netcfg_rpm,
            'update_rpm' : self._update_netcfg_rpm,
        }
        self.oper_shell = {
            'CMD_SSHPASS_PRE' : "sshpass -p ossdbg1 %(ssh_ip)s %(cmd)s",
            'CMD_RPM_UNINSTALL' : "rpm -e network-configuration",
            'CMD_RPM_INSTALL' : "rpm -i /home/network-configuration-1.1.1-15.x86_64.rpm",
            'CMD_RPM_UPDATE' : "rpm -U /home/network-configuration-1.1.1-15.x86_64.rpm",
            'CMD_RPM_SCP' : "scp %(path)s root@%(ssh_ip)s:/home" %
                            {'path': self.NETCFG_RPM_PATH, 'ssh_ip':mgnt_ip}
        }

        self._execute()

    def _uninstall_netcfg_rpm(self):
        self.clush_cmd = self.oper_shell['CMD_SSHPASS_PRE'] % \
                        {"ssh_ip":"ssh " + self.mgnt_ip, "cmd":self.oper_shell['CMD_RPM_UNINSTALL']}
        subprocess.check_output(self.clush_cmd, shell = True, stderr=subprocess.STDOUT)

    def _update_netcfg_rpm(self):
        self.clush_cmd = self.oper_shell['CMD_SSHPASS_PRE'] % \
                        {"ssh_ip":"ssh " + self.mgnt_ip, "cmd":self.oper_shell['CMD_RPM_UPDATE']}
        subprocess.check_output(self.clush_cmd, shell = True, stderr=subprocess.STDOUT)

    def _install_netcfg_rpm(self):
        if not os.path.exists(self.NETCFG_RPM_PATH):
            LOG.error(_("<<<Rpm %s not exist>>>" % self.NETCFG_RPM_PATH))
            return

        self.clush_cmd = "%s;%s" % \
                        (self.oper_shell['CMD_SSHPASS_PRE'] %
                            {"ssh_ip":"", "cmd":self.oper_shell['CMD_RPM_SCP']}, \
                         self.oper_shell['CMD_SSHPASS_PRE'] %
                            {"ssh_ip":"ssh " + self.mgnt_ip, "cmd":self.oper_shell['CMD_RPM_INSTALL']})
        subprocess.check_output(self.clush_cmd, shell = True, stderr=subprocess.STDOUT)

    def _execute(self):
        try:
            if not self.task_type or not self.mgnt_ip :
                LOG.error(_("<<<TecsShellExector::execute, input params invalid!>>>"))
                return

            self.oper_type[self.task_type]()
        except subprocess.CalledProcessError as e:
            LOG.warn(_("<<<TecsShellExector::execute:Execute command failed! Reason:%s>>>" % e.output.strip()))
        except Exception as e:
            LOG.exception(_(e.message))
        else:
            LOG.info(_("<<<TecsShellExector::execute:Execute command:%s,successful!>>>" % self.clush_cmd))
