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

import webob.exc
import subprocess

from oslo_config import cfg
from oslo_log import log as logging
from webob.exc import HTTPBadRequest
from webob.exc import HTTPForbidden

from threading import Thread, Lock
import threading
from daisy import i18n
from daisy import notifier

from daisy.api import policy
import daisy.api.v1

from daisy.common import exception
from daisy.common import property_utils
from daisy.common import utils
from daisy.common import wsgi
from daisy.api.v1 import controller
from daisy.api.v1 import filters
import daisy.api.backends.common as daisy_cmn
import daisy.api.backends.tecs.common as tecs_cmn
import daisy.registry.client.v1.api as registry

LOG = logging.getLogger(__name__)
_ = i18n._
_LE = i18n._LE
_LI = i18n._LI
_LW = i18n._LW

tecs_state = tecs_cmn.TECS_STATE

# uninstall init progress is 100, when uninstall succefully, 
# uninstall progress is 0, and web display progress is reverted
uninstall_tecs_progress=100.0
uninstall_mutex = threading.Lock()

def update_progress_to_db(req, role_id_list, status, hosts_list, progress_percentage_step=0.0):
    """
    Write uninstall progress and status to db, we use global lock object 'uninstall_mutex'
    to make sure this function is thread safety.
    :param req: http req.
    :param role_id_list: Column neeb be update in role table.
    :param status: Uninstall status.
    :return:
    """

    global uninstall_mutex
    global uninstall_tecs_progress
    uninstall_mutex.acquire(True)
    uninstall_tecs_progress -= progress_percentage_step
    role = {}
    for role_id in role_id_list:
        role_hosts = daisy_cmn.get_hosts_of_role(req, role_id)
        if 0 == cmp(status, tecs_state['UNINSTALLING']):
            role['status'] = status
            role['progress'] = uninstall_tecs_progress
            role['messages'] = 'Tecs uninstalling'
            for role_host in role_hosts:
                role_host_meta = {}
                role_host_meta['status'] = status
                role_host_meta['progress'] = uninstall_tecs_progress
                daisy_cmn.update_role_host(req, role_host['id'], role_host_meta)
        if 0 == cmp(status,  tecs_state['UNINSTALL_FAILED']):
            role['status'] = status
            role['messages'] = 'Uninstall-failed log at /var/log/daisy/daisy_uninstall'
            for role_host in role_hosts:
                role_host_meta = {}
                role_host_meta['status'] = status
                daisy_cmn.update_role_host(req, role_host['id'], role_host_meta)
        elif 0 == cmp(status, "init"):
            role['status'] = status
            role['progress'] = 0
            role['messages'] = 'Tecs uninstall successfully'
            host_meta = {}
            for host in hosts_list:
                host_meta['status'] = 'in-cluster'
                registry.update_host_metadata(req.context, host.keys()[0], host_meta)
            daisy_cmn.delete_role_hosts(req, role_id)

        daisy_cmn.update_role(req, role_id, role)
    uninstall_mutex.release()

def _thread_bin(req, host_ip, role_id_list,uninstall_progress_percentage):
    # uninstall network-configuration-1.1.1-15.x86_64.rpm
    tecs_cmn.TecsShellExector(host_ip, 'uninstall_rpm')

    cmd = 'mkdir -p /var/log/daisy/daisy_uninstall/'
    daisy_cmn.subprocess_call(cmd)
    password = "ossdbg1"   
    var_log_path = "/var/log/daisy/daisy_uninstall/%s_uninstall_tecs.log" % host_ip
    with open(var_log_path, "w+") as fp:
        cmd = '/var/lib/daisy/tecs/trustme.sh %s %s' % (host_ip, password)
        daisy_cmn.subprocess_call(cmd,fp)
        cmd = 'clush -S -b -w %s "rm -rf /home/daisy_uninstall"' % (host_ip,)
        daisy_cmn.subprocess_call(cmd,fp)
        cmd = 'clush -S -w %s "mkdir -p /home/daisy_uninstall"' % (host_ip,)
        daisy_cmn.subprocess_call(cmd,fp)
        cmd = 'clush -S -w %s -c /var/lib/daisy/tecs/ZXTECS*.bin --dest=/home/daisy_uninstall' % (host_ip,)
        daisy_cmn.subprocess_call(cmd,fp)
        cmd = 'clush -S -w %s "chmod 777 /home/daisy_uninstall/*"' % (host_ip,)
        daisy_cmn.subprocess_call(cmd,fp)
        
        try:
            exc_result = subprocess.check_output(
                'clush -S -w %s /home/daisy_uninstall/ZXTECS*.bin clean' % (host_ip,),
                shell=True, stderr=subprocess.STDOUT)
        except subprocess.CalledProcessError as e:
            update_progress_to_db(req, role_id_list, tecs_state['UNINSTALL_FAILED'])
            LOG.info(_("Uninstall TECS for %s failed!" % host_ip))
            fp.write(e.output.strip())
        else:
            update_progress_to_db(req, role_id_list, tecs_state['UNINSTALLING'], uninstall_progress_percentage)
            LOG.info(_("Uninstall TECS for %s successfully!" % host_ip))
            fp.write(exc_result)
# this will be raise raise all the exceptions of the thread to log file
def thread_bin(req, host_ip, role_id_list, uninstall_progress_percentage):
    try:
        _thread_bin(req, host_ip, role_id_list, uninstall_progress_percentage)
    except Exception as e:
        LOG.exception(e.message)