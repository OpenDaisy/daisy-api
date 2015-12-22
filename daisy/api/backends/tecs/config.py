# -*- coding: utf-8 -*-
import os
import re
import commands
import types
import subprocess
from ConfigParser import ConfigParser
from daisy.common import exception


service_map = {
    'lb': 'haproxy',
    'mongodb': 'mongod',
    'ha': '',
    'mariadb': 'mariadb',
    'amqp': 'rabbitmq-server',
    'ceilometer-api':'openstack-ceilometer-api',
    'ceilometer-collector':'openstack-ceilometer-collector,openstack-ceilometer-mend',
    'ceilometer-central':'openstack-ceilometer-central',
    'ceilometer-notification':'openstack-ceilometer-notification',
    'ceilometer-alarm':'openstack-ceilometer-alarm-evaluator,openstack-ceilometer-alarm-notifier',
    'heat-api': 'openstack-heat-api',
    'heat-api-cfn': 'openstack-heat-api-cfn',
    'heat-engine': 'openstack-heat-engine',
    'ironic': 'openstack-ironic-api,openstack-ironic-conductor',
    'horizon': 'httpd',
    'keystone': 'openstack-keystone',
    'glance': 'openstack-glance-api,openstack-glance-registry',
    'cinder-volume': 'openstack-cinder-volume',
    'cinder-scheduler': 'openstack-cinder-scheduler',
    'cinder-api': 'openstack-cinder-api',
    'neutron-metadata': 'neutron-metadata-agent',
    'neutron-lbaas': 'neutron-lbaas-agent',
    'neutron-dhcp': 'neutron-dhcp-agent',
    'neutron-server': 'neutron-server',
    'neutron-l3': 'neutron-l3-agent',
    'compute': 'openstack-nova-compute',
    'nova-cert': 'openstack-nova-cert',
    'nova-sched': 'openstack-nova-scheduler',
    'nova-vncproxy': 'openstack-nova-novncproxy,openstack-nova-consoleauth',
    'nova-conductor': 'openstack-nova-conductor',
    'nova-api': 'openstack-nova-api'
    }


def add_service_with_host(services, name, host):
    if name not in services:
        services[name] = []
    services[name].append(host)


def add_service_with_hosts(services, name, hosts):
    if name not in services:
        services[name] = []
    for h in hosts:
        services[name].append(h['management']['ip'])

def test_ping(ping_src_nic, ping_desc_ips):
    ping_cmd = 'fping'
    for ip in set(ping_desc_ips):
        ping_cmd = ping_cmd + ' -I ' + ping_src_nic + ' ' + ip
    obj = subprocess.Popen(ping_cmd, shell=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
    (stdoutput, erroutput) = obj.communicate() 
    _returncode = obj.returncode
    if _returncode == 0 or _returncode == 1:
        ping_result = stdoutput.split('\n')
        unreachable_hosts = [result.split()[0] for result in ping_result if result and result.split()[2] != 'alive']
    else:
        msg = "ping failed beaceuse there is invlid ip in %s" % ping_desc_ips
        raise exception.InvalidIP(msg)
    return unreachable_hosts

def get_local_deployment_ip(tecs_deployment_ip):
    def _get_ip_segment(full_ip):
        if not full_ip:
            return None
        match = re.search('([0-9]{1,3}\.){3}', full_ip)
        if match:
            return match.group()
        else:
            print "can't find ip segment"
            return None
    
    (status, output) = commands.getstatusoutput('ifconfig')
    netcard_pattern = re.compile('\S*: ')
    ip_str = '([0-9]{1,3}\.){3}[0-9]{1,3}'
    ip_pattern = re.compile('(inet %s)' % ip_str)
    pattern = re.compile(ip_str)
    nic_ip = {}
    for netcard in re.finditer(netcard_pattern, str(output)):
        nic_name = netcard.group().split(':')[0]
        if nic_name == "lo":
            continue
        ifconfig_nic_cmd = "ifconfig %s" % nic_name
        (status, output) = commands.getstatusoutput(ifconfig_nic_cmd)
        if status:
            continue
        ip = pattern.search(str(output))
        if ip and ip.group() != "127.0.0.1":
            nic_ip[nic_name] = ip.group()

    deployment_ip = ''
    ip_segment = _get_ip_segment(tecs_deployment_ip)
    for nic in nic_ip.keys():
        if ip_segment == _get_ip_segment(nic_ip[nic]):
            deployment_ip = nic_ip[nic]
            break
    if not deployment_ip:
        for nic,ip in nic_ip.items():
            if not test_ping(nic,[tecs_deployment_ip]):
                deployment_ip = nic_ip[nic]
                break
    return deployment_ip


class AnalsyConfig(object):
    def __init__(self, all_configs):
        self.all_configs = all_configs

        self.services = {}
        self.components = []
        self.modes = {}
        # self.ha_conf = {}
        self.services_in_component = {}
        # self.heartbeat = {}
        self.lb_components = []
        self.heartbeats = [[], [], []]
        self.lb_vip = ''
        self.ha_vip = ''
        self.ha_conf = {}

    def update_config(self, tecs, ha,ha_nic_name):
        self.prepare()
        self.update_conf_with_services(tecs)
        self.update_conf_with_components(tecs)
        self.update_conf_with_modes(tecs)
        self.update_ha_conf(ha, ha_nic_name)

    def get_heartbeats(self, host_interfaces):
        for network in host_interfaces:
            #if network.has_key("deployment") and network["deployment"]["ip"]:
            #    self.heartbeats[0].append(network["deployment"]["ip"])
            self.heartbeats[0].append(network["management"]["ip"])
            if network.has_key("storage") and network["storage"]["ip"]:
                self.heartbeats[1].append(network["storage"]["ip"])

        #delete empty heartbeat line
        if not self.heartbeats[0]:
             self.heartbeats[0] = self.heartbeats[1]
             self.heartbeats[1] = self.heartbeats[2]
        if not self.heartbeats[1]:
           self.heartbeats[1] = self.heartbeats[2]

        # remove repeated ip
        if set(self.heartbeats[1]) == set(self.heartbeats[0]):
            self.heartbeats[1] = []
            if set(self.heartbeats[2]) != set(self.heartbeats[0]):
                self.heartbeats[1] = self.heartbeats[2]
                self.heartbeats[2] = []
        if set(self.heartbeats[2]) == set(self.heartbeats[0]) or set(self.heartbeats[2]) == set(self.heartbeats[1]):
            self.heartbeats[2] = []

    def prepare(self):
        for role_name, role_configs in self.all_configs.items():
            if role_name == "OTHER":
                continue
            is_ha = re.match(".*_HA$", role_name) is not None
            is_lb = re.match(".*_LB$", role_name) is not None

            if is_lb:
                self.components.append('CONFIG_LB_INSTALL')
                add_service_with_hosts(self.services, 'CONFIG_LB_BACKEND_HOSTS', role_configs['host_interfaces'])
                self.lb_vip = role_configs['vip']
            if is_ha:
                self.ha_vip = role_configs['vip']
                #add by 10166727--------start-----------
                host_mgnt_ip=''
                host_mngt_ip_list=role_configs['host_interfaces'][0]['management']['ip'].split(",")
                for host_mngt_ip in host_mngt_ip_list:
                    if str('MANAGEMENT')==str(host_mngt_ip.split(':')[0]):
                            host_mgnt_ip = host_mngt_ip.split(':')[1]
                #add by 10166727--------end-------------
                local_deployment_ip = get_local_deployment_ip(host_mgnt_ip)
                if local_deployment_ip:
                    add_service_with_host(self.services, 'CONFIG_REPO', 'http://'+local_deployment_ip+'/tecs_install/')
                else:
                    msg = "can't find ip for yum repo"
                    raise exception.InvalidNetworkConfig(msg)
                self.components.append('CONFIG_HA_INSTALL')
                add_service_with_host(self.services, 'CONFIG_HA_HOST',
                                      role_configs['host_interfaces'][0]['management']['ip'])
                add_service_with_hosts(self.services, 'CONFIG_HA_HOSTS', role_configs['host_interfaces'])
                add_service_with_host(self.services, 'CONFIG_NTP_SERVERS', role_configs['vip'])

            for service, component in role_configs['services'].items():
                s = service.strip().upper().replace('-', '_')
                host_key_name = "CONFIG_%s_HOST" % s
                hosts_key_name = "CONFIG_%s_HOSTS" % s

                add_service_with_hosts(self.services, hosts_key_name, role_configs['host_interfaces'])
                if s != 'LB':
                    add_service_with_host(self.services, host_key_name, role_configs['vip'])

                if is_ha and s == 'LB':
                    add_service_with_hosts(self.services, 'CONFIG_LB_FRONTEND_HOSTS', role_configs['host_interfaces'])

                mode_key = "CONFIG_%s_INSTALL_MODE" % s
                if is_ha:
                    self.modes.update({mode_key: 'HA'})
                elif is_lb:
                    self.modes.update({mode_key: 'LB'})
                    # special process
                    if s == 'GLANCE':
                        self.modes.update({'CONFIG_GLANCE_API_INSTALL_MODE': 'LB'})
                        self.modes.update({'CONFIG_GLANCE_REGISTRY_INSTALL_MODE': 'LB'})
                    #if s == 'HEAT':
                    #    self.modes.update({'CONFIG_HEAT_API_INSTALL_MODE': 'LB'})
                    #    self.modes.update({'CONFIG_HEAT_API_CFN_INSTALL_MODE': 'LB'})
                    #if s == 'CEILOMETER':
                    #    self.modes.update({'CONFIG_CEILOMETER_API_INSTALL_MODE': 'LB'})
                    if s == 'IRONIC':
                        self.modes.update({'CONFIG_IRONIC_API_INSTALL_MODE': 'LB'})
                else:
                    self.modes.update({mode_key: 'None'})

                if is_lb:
                    self.lb_components.append(component)

                c = "CONFIG_%s_INSTALL" % component.strip().upper().replace('-', '_')
                self.components.append(c)

                if is_ha:
                    if component not in self.services_in_component.keys():
                        self.services_in_component[component] = {}
                        self.services_in_component[component]["service"] = []
                    self.services_in_component[component]["service"].append(service_map[service])
                    self.services_in_component[component]["fip"] = role_configs["vip"]
                    self.services_in_component[component]["netmask"] = \
                        role_configs["host_interfaces"][0]["management"]["netmask"]
                    self.services_in_component[component]["nic_name"] = \
                        role_configs["host_interfaces"][0]["management"]["name"]
                    if component == 'loadbalance' and \
                       self.all_configs.has_key('CONTROLLER_LB') and \
                       self.all_configs['CONTROLLER_LB']['vip']:
                            self.services_in_component[component]["fip"] = \
                                self.all_configs['CONTROLLER_LB']['vip']
            if is_ha:
                self.get_heartbeats(role_configs['host_interfaces'])
            pass

        if self.lb_vip:
            amqp_dict = "{'%s':'%s,%s'}" % (self.ha_vip, self.ha_vip, self.lb_vip)
            mariadb_dict = "{'%s':'%s,%s'}" % (self.ha_vip, self.ha_vip, self.lb_vip)
            add_service_with_host(self.services, 'CONFIG_LB_HOST', self.lb_vip)
        elif self.ha_vip:
            amqp_dict = "{'%s':'%s'}" % (self.ha_vip, self.ha_vip)
            mariadb_dict = "{'%s':'%s'}" % (self.ha_vip, self.ha_vip)
        else:
            amqp_dict = "{}"
            mariadb_dict = "{}"
        if self.lb_vip or self.ha_vip:
            add_service_with_host(self.services, 'CONFIG_MARIADB_DICT', mariadb_dict)
            add_service_with_host(self.services, 'CONFIG_AMQP_DICT', amqp_dict)

    def update_conf_with_services(self, tecs):
        for s in self.services:
            if tecs.has_option("general", s):
                print "%s is update" % s
                if type(self.services[s]) is types.ListType:
                    if self.services[s] and not self.services[s][0]:
                        return
                tecs.set("general", s, ','.join(self.services[s]))
            else:
                print "service %s is not exit in conf file" % s

    def update_conf_with_components(self, tecs):
        for s in self.components:
            if tecs.has_option("general", s):
                print "Component %s is update" % s
                tecs.set("general", s, 'y')
            else:
                print "component %s is not exit in conf file" % s

    def update_ha_conf(self, ha, ha_nic_name):
        print "heartbeat line is update"
        ha.set('DEFAULT', 'heartbeat_link1', ','.join(self.heartbeats[0]))
        ha.set('DEFAULT', 'heartbeat_link2', ','.join(self.heartbeats[1]))
        ha.set('DEFAULT', 'heartbeat_link3', ','.join(self.heartbeats[2]))

        ha.set('DEFAULT', 'components', ','.join(self.services_in_component.keys()))

        for k, v in self.services_in_component.items():
            print "component %s is update" % k
            ha.set('DEFAULT', k, ','.join(v['service']))
            if k == "glance":
                ha.set('DEFAULT', 'glance_device_type', 'drbd')
                ha.set('DEFAULT', 'glance_device', '/dev/vg_data/lv_glance')
                ha.set('DEFAULT', 'glance_fs_type', 'ext4')
            if k not in self.lb_components:
                # if "bond" in v['nic_name']:
                    # v['nic_name'] = "vport"
                ha.set('DEFAULT', k+'_fip', v['fip'])
                if ha_nic_name:
                    nic_name = ha_nic_name
                else:
                    nic_name = v['nic_name']
                ha.set('DEFAULT', k+'_nic', nic_name)
                cidr_netmask = reduce(lambda x, y: x + y,
                                      [bin(int(i)).count('1') for i in v['netmask'].split('.')])
                ha.set('DEFAULT', k+'_netmask', cidr_netmask)

    def update_conf_with_modes(self, tecs):
        for k, v in self.modes.items():
            if tecs.has_option("general", k):
                print "mode %s is update" % k
                tecs.set("general", k, v)
            else:
                print "mode %s is not exit in conf file" % k


def update_conf(tecs, key, value):
    tecs.set("general", key, value)

def get_conf(tecs_conf_file, **kwargs):
    result = {}
    if not kwargs:
        return  result

    tecs = ConfigParser()
    tecs.optionxform = str
    tecs.read(tecs_conf_file)

    result = {key : tecs.get("general",  kwargs.get(key, None))
              for key in kwargs.keys()
              if tecs.has_option("general", kwargs.get(key, None))}
    return result

default_tecs_conf_template_path = "/var/lib/daisy/tecs/"
tecs_conf_template_path = default_tecs_conf_template_path

def private_network_conf(tecs, private_networks_config):
    if private_networks_config:
        mode_str = {
            '0':'(active-backup;off;"%s-%s")',
            '1':'(balance-slb;off;"%s-%s")',
            '2':'(balance-tcp;active;"%s-%s")'
        }

        config_neutron_sriov_bridge_mappings = []
        config_neutron_sriov_physnet_ifaces = []
        config_neutron_ovs_bridge_mappings = []
        config_neutron_ovs_physnet_ifaces = []
        for private_network in private_networks_config:
            type = private_network.get('type', None)
            name = private_network.get('name', None)
            assign_networks = private_network.get('assigned_networks', None)
            slave1 =  private_network.get('slave1', None)
            slave2 =  private_network.get('slave2', None)
            mode = private_network.get('mode', None)
            if not type or not name or not assign_networks or not slave1 or not slave2 or not mode:
                break

            for assign_network in assign_networks:
                network_type = assign_network.get('network_type', None)
                # TODO:why ml2_type & physnet_name is null
                ml2_type = assign_network.get('ml2_type', None)
                physnet_name = assign_network.get('physnet_name', None)
                if not network_type or not ml2_type or not physnet_name:
                    break

                # ether
                if 0 == cmp(type, 'ether') and 0 == cmp(network_type, 'PRIVATE'):
                    if 0 == cmp(ml2_type, 'sriov'):
                        config_neutron_sriov_bridge_mappings.append("%s:%s" % (physnet_name, "br-" + name))
                        config_neutron_sriov_physnet_ifaces.append("%s:%s" % (physnet_name, name))
                    elif 0 == cmp(ml2_type, 'ovs'):
                        config_neutron_ovs_bridge_mappings.append("%s:%s" % (physnet_name, "br-" + name))
                        config_neutron_ovs_physnet_ifaces.append("%s:%s" % (physnet_name, name))
                # bond
                elif 0 == cmp(type, 'bond') and 0 == cmp(network_type, 'PRIVATE'):
                    if 0 == cmp(ml2_type, 'sriov'):
                        config_neutron_sriov_bridge_mappings.append("%s:%s" % (physnet_name, "br-" + name))
                        config_neutron_sriov_physnet_ifaces.append(
                            "%s:%s" % (physnet_name, name +  mode_str[mode] % (slave1, slave2)))
                    elif 0 == cmp(ml2_type, 'ovs'):
                        config_neutron_ovs_bridge_mappings.append("%s:%s" % (physnet_name, "br-" + name))
                        config_neutron_ovs_physnet_ifaces.append(
                            "%s:%s" % (physnet_name, name +  mode_str[mode] % (slave1, slave2)))

        if config_neutron_sriov_bridge_mappings:
            update_conf(tecs,
                        'CONFIG_NEUTRON_SRIOV_BRIDGE_MAPPINGS',
                        ",".join(config_neutron_sriov_bridge_mappings))
        if config_neutron_sriov_physnet_ifaces:
            update_conf(tecs,
                        'CONFIG_NEUTRON_SRIOV_PHYSNET_IFACES',
                        ",".join(config_neutron_sriov_physnet_ifaces))
        if config_neutron_ovs_bridge_mappings :
            update_conf(tecs, 'CONFIG_NEUTRON_OVS_BRIDGE_MAPPINGS', ",".join(config_neutron_ovs_bridge_mappings))
        if config_neutron_ovs_physnet_ifaces:
            update_conf(tecs, 'CONFIG_NEUTRON_OVS_PHYSNET_IFACES', ",".join(config_neutron_ovs_physnet_ifaces))

def update_tecs_conf(config_data, cluster_conf_path):
    print "tecs config data is:"
    import pprint
    pprint.pprint(config_data)
    
    daisy_tecs_path = tecs_conf_template_path
    tecs_conf_template_file = os.path.join(daisy_tecs_path, "tecs.conf")
    ha_conf_template_file = os.path.join(daisy_tecs_path, "HA.conf")
    if not os.path.exists(cluster_conf_path):
        os.makedirs(cluster_conf_path)
    tecs_conf_out = os.path.join(cluster_conf_path, "tecs.conf")
    ha_config_out = os.path.join(cluster_conf_path, "HA_1.conf")

    tecs = ConfigParser()
    tecs.optionxform = str
    tecs.read(tecs_conf_template_file)
    
    cluster_data = config_data['OTHER']['cluster_data']
    update_conf(tecs, 'CLUSTER_ID', cluster_data['id'])
    if cluster_data.has_key('networking_parameters'):
        networking_parameters = cluster_data['networking_parameters']
        if networking_parameters.has_key('base_mac') and networking_parameters['base_mac']:
            update_conf(tecs, 'CONFIG_NEUTRON_BASE_MAC', networking_parameters['base_mac'])
        if networking_parameters.has_key('gre_id_range') and len(networking_parameters['gre_id_range'])>1 \
            and networking_parameters['gre_id_range'][0] and networking_parameters['gre_id_range'][1]: 
            update_conf(tecs, 'CONFIG_NEUTRON_ML2_TUNNEL_ID_RANGES', ("%s:%s" % (networking_parameters['gre_id_range'][0],networking_parameters['gre_id_range'][1])))
        if networking_parameters.get("vni_range",['1000','3000']) and len(networking_parameters['vni_range'])>1 \
            and networking_parameters['vni_range'][0] and networking_parameters['vni_range'][1]: 
            update_conf(tecs, 'CONFIG_NEUTRON_ML2_VNI_RANGES', ("%s:%s" % (networking_parameters['vni_range'][0],networking_parameters['vni_range'][1])))
        if networking_parameters.get("segmentation_type","vlan"):
            segmentation_type = networking_parameters.get("segmentation_type","vlan")
            update_conf(tecs, 'CONFIG_NEUTRON_ML2_TENANT_NETWORK_TYPES', segmentation_type)
            update_conf(tecs, 'CONFIG_NEUTRON_ML2_TYPE_DRIVERS', segmentation_type)

    physic_network_cfg = config_data['OTHER']['physic_network_config']
    if physic_network_cfg.get('json_path', None):
        update_conf(tecs, 'CONFIG_NEUTRON_ML2_JSON_PATH', physic_network_cfg['json_path'])
    if physic_network_cfg.get('vlan_ranges', None):
        update_conf(tecs, 'CONFIG_NEUTRON_ML2_VLAN_RANGES',physic_network_cfg['vlan_ranges'])
    if config_data['OTHER']['tecs_installed_hosts']:
            update_conf(tecs, 'EXCLUDE_SERVERS', ",".join(config_data['OTHER']['tecs_installed_hosts']))

    ha = ConfigParser()
    ha.optionxform = str
    ha.read(ha_conf_template_file)

    config = AnalsyConfig(config_data)
    if config_data['OTHER'].has_key('ha_nic_name'):
        ha_nic_name = config_data['OTHER']['ha_nic_name']
    else:
        ha_nic_name = ""
    config.update_config(tecs, ha,ha_nic_name)

    tecs.write(open(tecs_conf_out, "w+"))
    ha.write(open(ha_config_out, "w+"))
    
    return


def test():
    print("Hello, world!")
