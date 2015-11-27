# Copyright 2012 OpenStack Foundation.
# All Rights Reserved
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
#

import httplib
import logging
import time
import urllib
import urlparse

from neutronclient import client
from neutronclient.common import _
from neutronclient.common import constants
from neutronclient.common import exceptions
from neutronclient.common import serializer
from neutronclient.common import utils
from neutronclient.v2_0 import APIParamsCall
from neutronclient.v2_0 import uos


_logger = logging.getLogger(__name__)


def exception_handler_v20(status_code, error_content):
    """Exception handler for API v2.0 client

        This routine generates the appropriate
        Neutron exception according to the contents of the
        response body

        :param status_code: HTTP error status code
        :param error_content: deserialized body of error response
    """

    neutron_errors = {
        'NetworkNotFound': exceptions.NetworkNotFoundClient,
        'NetworkInUse': exceptions.NetworkInUseClient,
        'PortNotFound': exceptions.PortNotFoundClient,
        'RequestedStateInvalid': exceptions.StateInvalidClient,
        'PortInUse': exceptions.PortInUseClient,
        'IpAddressInUse': exceptions.IpAddressInUseClient,
        'AlreadyAttached': exceptions.AlreadyAttachedClient,
        'IpAddressGenerationFailure':
        exceptions.IpAddressGenerationFailureClient,
        'ExternalIpAddressExhausted':
        exceptions.ExternalIpAddressExhaustedClient, }

    error_dict = None
    if isinstance(error_content, dict):
        error_dict = error_content.get('NeutronError')
    # Find real error type
    bad_neutron_error_flag = False
    if error_dict:
        # If Neutron key is found, it will definitely contain
        # a 'message' and 'type' keys?
        try:
            error_type = error_dict['type']
            error_message = (error_dict['message'] + "\n" +
                             error_dict['detail'])
        except Exception:
            bad_neutron_error_flag = True
        if not bad_neutron_error_flag:
            ex = None
            try:
                # raise the appropriate error!
                ex = neutron_errors[error_type](message=error_message,
                                                status_code=status_code)
            except Exception:
                pass
            if ex:
                raise ex
        else:
            raise exceptions.NeutronClientException(status_code=status_code,
                                                    message=error_dict)
    else:
        message = None
        if isinstance(error_content, dict):
            message = error_content.get('message', None)
        if message:
            raise exceptions.NeutronClientException(status_code=status_code,
                                                    message=message)

    # If we end up here the exception was not a neutron error
    msg = "%s-%s" % (status_code, error_content)
    raise exceptions.NeutronClientException(status_code=status_code,
                                            message=msg)


class Client(uos.UosClientMixin):
    """Client for the OpenStack Neutron v2.0 API.

    :param string username: Username for authentication. (optional)
    :param string password: Password for authentication. (optional)
    :param string token: Token for authentication. (optional)
    :param string tenant_name: Tenant name. (optional)
    :param string tenant_id: Tenant id. (optional)
    :param string auth_url: Keystone service endpoint for authorization.
    :param string endpoint_type: Network service endpoint type to pull from the
                                 keystone catalog (e.g. 'publicURL',
                                 'internalURL', or 'adminURL') (optional)
    :param string region_name: Name of a region to select when choosing an
                               endpoint from the service catalog.
    :param string endpoint_url: A user-supplied endpoint URL for the neutron
                            service.  Lazy-authentication is possible for API
                            service calls if endpoint is set at
                            instantiation.(optional)
    :param integer timeout: Allows customization of the timeout for client
                            http requests. (optional)
    :param bool insecure: SSL certificate validation. (optional)
    :param string ca_cert: SSL CA bundle file to use. (optional)

    Example::

        from neutronclient.v2_0 import client
        neutron = client.Client(username=USER,
                                password=PASS,
                                tenant_name=TENANT_NAME,
                                auth_url=KEYSTONE_URL)

        nets = neutron.list_networks()
        ...

    """

    networks_path = "/networks"
    network_path = "/networks/%s"
    ports_path = "/ports"
    port_path = "/ports/%s"
    subnets_path = "/subnets"
    subnet_path = "/subnets/%s"
    quotas_path = "/quotas"
    quota_path = "/quotas/%s"
    extensions_path = "/extensions"
    extension_path = "/extensions/%s"
    routers_path = "/routers"
    router_path = "/routers/%s"
    floatingips_path = "/floatingips"
    floatingip_path = "/floatingips/%s"
    security_groups_path = "/security-groups"
    security_group_path = "/security-groups/%s"
    security_group_rules_path = "/security-group-rules"
    security_group_rule_path = "/security-group-rules/%s"
    vpnservices_path = "/vpn/vpnservices"
    vpnservice_path = "/vpn/vpnservices/%s"
    ipsecpolicies_path = "/vpn/ipsecpolicies"
    ipsecpolicy_path = "/vpn/ipsecpolicies/%s"
    ikepolicies_path = "/vpn/ikepolicies"
    ikepolicy_path = "/vpn/ikepolicies/%s"
    ipsec_site_connections_path = "/vpn/ipsec-site-connections"
    ipsec_site_connection_path = "/vpn/ipsec-site-connections/%s"
    lbaas_loadbalancers_path = "/lbaas/loadbalancers"
    lbaas_loadbalancer_path = "/lbaas/loadbalancers/%s"
    lbaas_listeners_path = "/lbaas/listeners"
    lbaas_listener_path = "/lbaas/listeners/%s"
    lbaas_pools_path = "/lbaas/pools"
    lbaas_pool_path = "/lbaas/pools/%s"
    lbaas_healthmonitors_path = "/lbaas/healthmonitors"
    lbaas_healthmonitor_path = "/lbaas/healthmonitors/%s"
    lbaas_members_path = lbaas_pool_path + "/members"
    lbaas_member_path = lbaas_pool_path + "/members/%s"

    lbaas_loadbalancer_listeners_path = lbaas_loadbalancer_path+"/lbaas_listeners"
    lbaas_listener_l7policies_path = lbaas_listener_path+"/lbaas_l7policies"
    lbaas_l7policies_path = "/lbaas/l7policies"
    lbaas_l7policy_path = "/lbaas/l7policies/%s"
    lbaas_stats_path = "/lbaas/loadbalancers/%s/stats"

    lbaas_tlscertificates_path = "/lbaas/tlscertificates"
    lbaas_tlscertificate_path = "/lbaas/tlscertificates/%s"
    lbaas_l7rules_path = lbaas_l7policy_path+"/rules"
    lbaas_l7rule_path = lbaas_l7policy_path+"/rules/%s"
    vips_path = "/lb/vips"
    vip_path = "/lb/vips/%s"
    pools_path = "/lb/pools"
    pool_path = "/lb/pools/%s"
    pool_path_stats = "/lb/pools/%s/stats"
    members_path = "/lb/members"
    member_path = "/lb/members/%s"
    health_monitors_path = "/lb/health_monitors"
    health_monitor_path = "/lb/health_monitors/%s"
    associate_pool_health_monitors_path = "/lb/pools/%s/health_monitors"
    disassociate_pool_health_monitors_path = (
        "/lb/pools/%(pool)s/health_monitors/%(health_monitor)s")
    qos_queues_path = "/qos-queues"
    qos_queue_path = "/qos-queues/%s"
    agents_path = "/agents"
    agent_path = "/agents/%s"
    network_gateways_path = "/network-gateways"
    network_gateway_path = "/network-gateways/%s"
    service_providers_path = "/service-providers"
    credentials_path = "/credentials"
    credential_path = "/credentials/%s"
    network_profiles_path = "/network_profiles"
    network_profile_path = "/network_profiles/%s"
    network_profile_bindings_path = "/network_profile_bindings"
    policy_profiles_path = "/policy_profiles"
    policy_profile_path = "/policy_profiles/%s"
    policy_profile_bindings_path = "/policy_profile_bindings"
    metering_labels_path = "/metering/metering-labels"
    metering_label_path = "/metering/metering-labels/%s"
    metering_label_rules_path = "/metering/metering-label-rules"
    metering_label_rule_path = "/metering/metering-label-rules/%s"
    DHCP_NETS = '/dhcp-networks'
    DHCP_AGENTS = '/dhcp-agents'
    L3_ROUTERS = '/l3-routers'
    L3_AGENTS = '/l3-agents'
    LOADBALANCER_POOLS = '/loadbalancer-pools'
    LOADBALANCER_AGENT = '/loadbalancer-agent'
    firewall_rules_path = "/fw/firewall_rules"
    firewall_rule_path = "/fw/firewall_rules/%s"
    firewall_policies_path = "/fw/firewall_policies"
    firewall_policy_path = "/fw/firewall_policies/%s"
    firewall_policy_insert_path = "/fw/firewall_policies/%s/insert_rule"
    firewall_policy_remove_path = "/fw/firewall_policies/%s/remove_rule"
    firewalls_path = "/fw/firewalls"
    firewall_path = "/fw/firewalls/%s"
    tunnels_path = "/tunnel/tunnels"
    tunnel_path = "/tunnel/tunnels/%s"
    target_networks_path = "/tunnel/target-networks"
    target_network_path = "/tunnel/target-networks/%s"
    tunnel_connections_path = "/tunnel/tunnel-connections"
    tunnel_connection_path = "/tunnel/tunnel-connections/%s"
    device_templates_path = '/vm/device-templates'
    device_template_path = '/vm/device-templates/%s'
    devices_path = '/vm/devices'
    device_path = '/vm/devices/%s'
    service_instances_path = '/vm/service-instances'
    service_instance_path = '/vm/service-instances/%s'
    service_type_path = '/vm/service-types'
    interface_attach_path = '/vm//devices/%s/attach_interface'
    interface_detach_path = '/vm/devices/%s/detach_interface'

    # API has no way to report plurals, so we have to hard code them
    EXTED_PLURALS = {'routers': 'router',
                     'floatingips': 'floatingip',
                     'service_types': 'service_type',
                     'service_definitions': 'service_definition',
                     'security_groups': 'security_group',
                     'security_group_rules': 'security_group_rule',
                     'ipsecpolicies': 'ipsecpolicy',
                     'ikepolicies': 'ikepolicy',
                     'ipsec_site_connections': 'ipsec_site_connection',
                     'vpnservices': 'vpnservice',
                     'vips': 'vip',
                     'pools': 'pool',
                     'members': 'member',
                     'health_monitors': 'health_monitor',
                     'quotas': 'quota',
                     'service_providers': 'service_provider',
                     'firewall_rules': 'firewall_rule',
                     'firewall_policies': 'firewall_policy',
                     'firewalls': 'firewall',
                     'metering_labels': 'metering_label',
                     'metering_label_rules': 'metering_label_rule',
                     'loadbalancers': 'loadbalancer',
                     'listeners': 'listener',
                     'lbaas_pools': 'lbaas_pool',
                     'lbaas_healthmonitors': 'lbaas_healthmonitor',
                     'lbaas_members': 'lbaas_member',
                     'l7policies': 'l7policy',
                     'healthmonitors': 'healthmonitor',
                     'target_networks': 'target_network',
                     'tunnel_connections': 'tunnel_connection',
                     'tunnels': 'tunnel',
                     'device_templates': 'device_template',
                     'service_instances': 'service_instance',
                     'service_types': 'service_type',
                     'devices': 'device',
                     }
    # 8192 Is the default max URI len for eventlet.wsgi.server
    MAX_URI_LEN = 8192 * 10

    def get_attr_metadata(self):
        if self.format == 'json':
            return {}
        old_request_format = self.format
        self.format = 'json'
        exts = self.list_extensions()['extensions']
        self.format = old_request_format
        ns = dict([(ext['alias'], ext['namespace']) for ext in exts])
        self.EXTED_PLURALS.update(constants.PLURALS)
        return {'plurals': self.EXTED_PLURALS,
                'xmlns': constants.XML_NS_V20,
                constants.EXT_NS: ns}

    @APIParamsCall
    def get_quotas_tenant(self, **_params):
        """Fetch tenant info in server's context for
        following quota operation.
        """
        return self.get(self.quota_path % 'tenant', params=_params)

    @APIParamsCall
    def list_quotas(self, **_params):
        """Fetch all tenants' quotas."""
        return self.get(self.quotas_path, params=_params)

    @APIParamsCall
    def show_quota(self, tenant_id, **_params):
        """Fetch information of a certain tenant's quotas."""
        return self.get(self.quota_path % (tenant_id), params=_params)

    @APIParamsCall
    def update_quota(self, tenant_id, body=None):
        """Update a tenant's quotas."""
        return self.put(self.quota_path % (tenant_id), body=body)

    @APIParamsCall
    def delete_quota(self, tenant_id):
        """Delete the specified tenant's quota values."""
        return self.delete(self.quota_path % (tenant_id))

    @APIParamsCall
    def list_extensions(self, **_params):
        """Fetch a list of all exts on server side."""
        return self.get(self.extensions_path, params=_params)

    @APIParamsCall
    def show_extension(self, ext_alias, **_params):
        """Fetch a list of all exts on server side."""
        return self.get(self.extension_path % ext_alias, params=_params)

    @APIParamsCall
    def list_ports(self, retrieve_all=True, **_params):
        """Fetches a list of all networks for a tenant."""
        # Pass filters in "params" argument to do_request
        return self.list('ports', self.ports_path, retrieve_all,
                         **_params)

    @APIParamsCall
    def show_port(self, port, **_params):
        """Fetches information of a certain network."""
        return self.get(self.port_path % (port), params=_params)

    @APIParamsCall
    def create_port(self, body=None):
        """Creates a new port."""
        return self.post(self.ports_path, body=body)

    @APIParamsCall
    def update_port(self, port, body=None):
        """Updates a port."""
        return self.put(self.port_path % (port), body=body)

    @APIParamsCall
    def delete_port(self, port, **params):
        """Deletes the specified port."""
        return self.delete(self.port_path % (port), params=params)

    @APIParamsCall
    def list_networks(self, retrieve_all=True, **_params):
        """Fetches a list of all networks for a tenant."""
        # Pass filters in "params" argument to do_request
        return self.list('networks', self.networks_path, retrieve_all,
                         **_params)

    @APIParamsCall
    def show_network(self, network, **_params):
        """Fetches information of a certain network."""
        return self.get(self.network_path % (network), params=_params)

    @APIParamsCall
    def create_network(self, body=None):
        """Creates a new network."""
        return self.post(self.networks_path, body=body)

    @APIParamsCall
    def update_network(self, network, body=None):
        """Updates a network."""
        return self.put(self.network_path % (network), body=body)

    @APIParamsCall
    def delete_network(self, network):
        """Deletes the specified network."""
        return self.delete(self.network_path % (network))

    @APIParamsCall
    def list_subnets(self, retrieve_all=True, **_params):
        """Fetches a list of all networks for a tenant."""
        return self.list('subnets', self.subnets_path, retrieve_all,
                         **_params)

    @APIParamsCall
    def show_subnet(self, subnet, **_params):
        """Fetches information of a certain subnet."""
        return self.get(self.subnet_path % (subnet), params=_params)

    @APIParamsCall
    def create_subnet(self, body=None):
        """Creates a new subnet."""
        return self.post(self.subnets_path, body=body)

    @APIParamsCall
    def update_subnet(self, subnet, body=None):
        """Updates a subnet."""
        return self.put(self.subnet_path % (subnet), body=body)

    @APIParamsCall
    def delete_subnet(self, subnet):
        """Deletes the specified subnet."""
        return self.delete(self.subnet_path % (subnet))

    @APIParamsCall
    def list_routers(self, retrieve_all=True, **_params):
        """Fetches a list of all routers for a tenant."""
        # Pass filters in "params" argument to do_request
        return self.list('routers', self.routers_path, retrieve_all,
                         **_params)

    @APIParamsCall
    def show_router(self, router, **_params):
        """Fetches information of a certain router."""
        return self.get(self.router_path % (router), params=_params)

    @APIParamsCall
    def create_router(self, body=None):
        """Creates a new router."""
        return self.post(self.routers_path, body=body)

    @APIParamsCall
    def update_router(self, router, body=None):
        """Updates a router."""
        return self.put(self.router_path % (router), body=body)

    @APIParamsCall
    def delete_router(self, router):
        """Deletes the specified router."""
        return self.delete(self.router_path % (router))

    @APIParamsCall
    def add_interface_router(self, router, body=None):
        """Adds an internal network interface to the specified router."""
        return self.put((self.router_path % router) + "/add_router_interface",
                        body=body)

    @APIParamsCall
    def remove_interface_router(self, router, body=None):
        """Removes an internal network interface from the specified router."""
        return self.put((self.router_path % router) +
                        "/remove_router_interface", body=body)

    @APIParamsCall
    def add_gateway_router(self, router, body=None):
        """Adds an external network gateway to the specified router."""
        return self.put((self.router_path % router),
                        body={'router': {'external_gateway_info': body}})

    @APIParamsCall
    def remove_gateway_router(self, router):
        """Removes an external network gateway from the specified router."""
        return self.put((self.router_path % router),
                        body={'router': {'external_gateway_info': {}}})

    @APIParamsCall
    def list_floatingips(self, retrieve_all=True, **_params):
        """Fetches a list of all floatingips for a tenant."""
        # Pass filters in "params" argument to do_request
        return self.list('floatingips', self.floatingips_path, retrieve_all,
                         **_params)

    @APIParamsCall
    def show_floatingip(self, floatingip, **_params):
        """Fetches information of a certain floatingip."""
        return self.get(self.floatingip_path % (floatingip), params=_params)

    @APIParamsCall
    def create_floatingip(self, body=None):
        """Creates a new floatingip."""
        return self.post(self.floatingips_path, body=body)

    @APIParamsCall
    def update_floatingip(self, floatingip, body=None):
        """Updates a floatingip."""
        return self.put(self.floatingip_path % (floatingip), body=body)

    @APIParamsCall
    def delete_floatingip(self, floatingip):
        """Deletes the specified floatingip."""
        return self.delete(self.floatingip_path % (floatingip))

    @APIParamsCall
    def create_security_group(self, body=None):
        """Creates a new security group."""
        return self.post(self.security_groups_path, body=body)

    @APIParamsCall
    def update_security_group(self, security_group, body=None):
        """Updates a security group."""
        return self.put(self.security_group_path %
                        security_group, body=body)

    @APIParamsCall
    def list_security_groups(self, retrieve_all=True, **_params):
        """Fetches a list of all security groups for a tenant."""
        return self.list('security_groups', self.security_groups_path,
                         retrieve_all, **_params)

    @APIParamsCall
    def show_security_group(self, security_group, **_params):
        """Fetches information of a certain security group."""
        return self.get(self.security_group_path % (security_group),
                        params=_params)

    @APIParamsCall
    def delete_security_group(self, security_group):
        """Deletes the specified security group."""
        return self.delete(self.security_group_path % (security_group))

    @APIParamsCall
    def create_security_group_rule(self, body=None):
        """Creates a new security group rule."""
        return self.post(self.security_group_rules_path, body=body)

    @APIParamsCall
    def delete_security_group_rule(self, security_group_rule):
        """Deletes the specified security group rule."""
        return self.delete(self.security_group_rule_path %
                           (security_group_rule))

    @APIParamsCall
    def list_security_group_rules(self, retrieve_all=True, **_params):
        """Fetches a list of all security group rules for a tenant."""
        return self.list('security_group_rules',
                         self.security_group_rules_path,
                         retrieve_all, **_params)

    @APIParamsCall
    def show_security_group_rule(self, security_group_rule, **_params):
        """Fetches information of a certain security group rule."""
        return self.get(self.security_group_rule_path % (security_group_rule),
                        params=_params)

    @APIParamsCall
    def list_vpnservices(self, retrieve_all=True, **_params):
        """Fetches a list of all configured VPNServices for a tenant."""
        return self.list('vpnservices', self.vpnservices_path, retrieve_all,
                         **_params)

    @APIParamsCall
    def show_vpnservice(self, vpnservice, **_params):
        """Fetches information of a specific VPNService."""
        return self.get(self.vpnservice_path % (vpnservice), params=_params)

    @APIParamsCall
    def create_vpnservice(self, body=None):
        """Creates a new VPNService."""
        return self.post(self.vpnservices_path, body=body)

    @APIParamsCall
    def update_vpnservice(self, vpnservice, body=None):
        """Updates a VPNService."""
        return self.put(self.vpnservice_path % (vpnservice), body=body)

    @APIParamsCall
    def delete_vpnservice(self, vpnservice):
        """Deletes the specified VPNService."""
        return self.delete(self.vpnservice_path % (vpnservice))

    @APIParamsCall
    def list_ipsec_site_connections(self, retrieve_all=True, **_params):
        """Fetches all configured IPsecSiteConnections for a tenant."""
        return self.list('ipsec_site_connections',
                         self.ipsec_site_connections_path,
                         retrieve_all,
                         **_params)

    @APIParamsCall
    def show_ipsec_site_connection(self, ipsecsite_conn, **_params):
        """Fetches information of a specific IPsecSiteConnection."""
        return self.get(
            self.ipsec_site_connection_path % (ipsecsite_conn), params=_params
        )

    @APIParamsCall
    def create_ipsec_site_connection(self, body=None):
        """Creates a new IPsecSiteConnection."""
        return self.post(self.ipsec_site_connections_path, body=body)

    @APIParamsCall
    def update_ipsec_site_connection(self, ipsecsite_conn, body=None):
        """Updates an IPsecSiteConnection."""
        return self.put(
            self.ipsec_site_connection_path % (ipsecsite_conn), body=body
        )

    @APIParamsCall
    def delete_ipsec_site_connection(self, ipsecsite_conn):
        """Deletes the specified IPsecSiteConnection."""
        return self.delete(self.ipsec_site_connection_path % (ipsecsite_conn))

    @APIParamsCall
    def list_ikepolicies(self, retrieve_all=True, **_params):
        """Fetches a list of all configured IKEPolicies for a tenant."""
        return self.list('ikepolicies', self.ikepolicies_path, retrieve_all,
                         **_params)

    @APIParamsCall
    def show_ikepolicy(self, ikepolicy, **_params):
        """Fetches information of a specific IKEPolicy."""
        return self.get(self.ikepolicy_path % (ikepolicy), params=_params)

    @APIParamsCall
    def create_ikepolicy(self, body=None):
        """Creates a new IKEPolicy."""
        return self.post(self.ikepolicies_path, body=body)

    @APIParamsCall
    def update_ikepolicy(self, ikepolicy, body=None):
        """Updates an IKEPolicy."""
        return self.put(self.ikepolicy_path % (ikepolicy), body=body)

    @APIParamsCall
    def delete_ikepolicy(self, ikepolicy):
        """Deletes the specified IKEPolicy."""
        return self.delete(self.ikepolicy_path % (ikepolicy))

    @APIParamsCall
    def list_ipsecpolicies(self, retrieve_all=True, **_params):
        """Fetches a list of all configured IPsecPolicies for a tenant."""
        return self.list('ipsecpolicies',
                         self.ipsecpolicies_path,
                         retrieve_all,
                         **_params)

    @APIParamsCall
    def show_ipsecpolicy(self, ipsecpolicy, **_params):
        """Fetches information of a specific IPsecPolicy."""
        return self.get(self.ipsecpolicy_path % (ipsecpolicy), params=_params)

    @APIParamsCall
    def create_ipsecpolicy(self, body=None):
        """Creates a new IPsecPolicy."""
        return self.post(self.ipsecpolicies_path, body=body)

    @APIParamsCall
    def update_ipsecpolicy(self, ipsecpolicy, body=None):
        """Updates an IPsecPolicy."""
        return self.put(self.ipsecpolicy_path % (ipsecpolicy), body=body)

    @APIParamsCall
    def delete_ipsecpolicy(self, ipsecpolicy):
        """Deletes the specified IPsecPolicy."""
        return self.delete(self.ipsecpolicy_path % (ipsecpolicy))

    @APIParamsCall
    def list_loadbalancers(self, retrieve_all=True, **_params):
        """Fetches a list of all loadbalancers for a tenant."""
        return self.list('loadbalancers', self.lbaas_loadbalancers_path,
                         retrieve_all, **_params)

    @APIParamsCall
    def list_lbaas_listeners(self,lbaas_loadbalancer, retrieve_all=True, **_params):
        """Fetches a list of all listeners for a loadbalancer."""
        return self.list('lbaas_listeners', self.lbaas_loadbalancer_listeners_path %lbaas_loadbalancer,
                         retrieve_all, **_params)
    @APIParamsCall
    def show_loadbalancer(self, lbaas_loadbalancer, **_params):
        """Fetches information for a load balancer."""
        return self.get(self.lbaas_loadbalancer_path % (lbaas_loadbalancer),
                        params=_params)

    @APIParamsCall
    def create_loadbalancer(self, body=None):
        """Creates a new load balancer."""
        return self.post(self.lbaas_loadbalancers_path, body=body)

    @APIParamsCall
    def update_loadbalancer(self, lbaas_loadbalancer, body=None):
        """Updates a load balancer."""
        return self.put(self.lbaas_loadbalancer_path % (lbaas_loadbalancer),
                        body=body)

    @APIParamsCall
    def delete_loadbalancer(self, lbaas_loadbalancer):
        """Deletes the specified load balancer."""
        return self.delete(self.lbaas_loadbalancer_path %
                           (lbaas_loadbalancer))

    @APIParamsCall
    def create_l7policy(self, body=None):
        """Creates a new l7policy."""
        return self.post(self.lbaas_l7policies_path, body=body)
 
    @APIParamsCall
    def update_l7policy(self,lbaas_l7policy, body=None):
        """Updates a l7policy."""
        return self.put(self.lbaas_l7policy_path % (lbaas_l7policy), body=body)

    @APIParamsCall
    def delete_l7policy(self, l7_policy):
        """Deletes the specified l7policy."""
        return self.delete(self.lbaas_l7policy_path % l7_policy)
    
    @APIParamsCall
    def list_l7policies(self, retrieve_all=True, **_params):
        """Fetches a list of all load balancer l7policies for a tenant."""
        # Pass filters in "params" argument to do_request
        return self.list('l7policies', self.lbaas_l7policies_path, retrieve_all,
                          **_params)
    
    @APIParamsCall
    def list_lbaas_l7policies(self,lbaas_listener, retrieve_all=True, **_params):
        """Fetches a list of all l7policies for a listener."""
        return self.list('lbaas_l7policies', self.lbaas_listener_l7policies_path %lbaas_listener,
                         retrieve_all, **_params)
    
    @APIParamsCall
    def show_l7policy(self, lbaas_l7policy,  **_params):
        """Fetches information of a certain l7policy."""
        return self.get(self.lbaas_l7policy_path % (lbaas_l7policy),
                        params=_params)
 
    @APIParamsCall
    def create_rule(self, lbaas_l7policy, body=None):
        """Creates a new l7rule."""
        return self.post(self.lbaas_l7rules_path % (lbaas_l7policy), body=body)
 
    @APIParamsCall
    def update_rule(self,lbaas_l7rule,lbaas_l7policy, body=None):
        """Updates a l7rule."""
        return self.put(self.lbaas_l7rule_path % (lbaas_l7policy,lbaas_l7rule), body=body)

    @APIParamsCall
    def delete_rule(self, l7_rule ,l7_policy):
        """Deletes the specified l7rule."""
        return self.delete(self.lbaas_l7rule_path % (l7_policy, l7_rule))
    
    @APIParamsCall
    def list_rules(self, lbaas_l7policy, retrieve_all=True, **_params):
        """Fetches a list of all load balancer l7rules for a tenant."""
        return self.list('rules', self.lbaas_l7rules_path % lbaas_l7policy,
                         retrieve_all, **_params)
    
    @APIParamsCall
    def show_rule(self, lbaas_l7rule,l7_policy,  **_params):
        """Fetches information of a certain l7rule."""
        return self.get(self.lbaas_l7rule_path % (l7_policy,lbaas_l7rule),
                        params=_params)
    
   
    @APIParamsCall
    def list_listeners(self, retrieve_all=True, **_params):
        """Fetches a list of all lbaas_listeners for a tenant."""
        return self.list('listeners', self.lbaas_listeners_path,
                         retrieve_all, **_params)

    @APIParamsCall
    def show_listener(self, lbaas_listener, **_params):
        """Fetches information for a lbaas_listener."""
        return self.get(self.lbaas_listener_path % (lbaas_listener),
                        params=_params)

    @APIParamsCall
    def create_listener(self, body=None):
        """Creates a new lbaas_listener."""
        return self.post(self.lbaas_listeners_path, body=body)

    @APIParamsCall
    def update_listener(self, lbaas_listener, body=None):
        """Updates a lbaas_listener."""
        return self.put(self.lbaas_listener_path % (lbaas_listener),
                        body=body)

    @APIParamsCall
    def delete_listener(self, lbaas_listener):
        """Deletes the specified lbaas_listener."""
        return self.delete(self.lbaas_listener_path % (lbaas_listener))

    @APIParamsCall
    def list_lbaas_pools(self, retrieve_all=True, **_params):
        """Fetches a list of all lbaas_pools for a tenant."""
        return self.list('pools', self.lbaas_pools_path,
                         retrieve_all, **_params)

    @APIParamsCall
    def show_lbaas_pool(self, lbaas_pool, **_params):
        """Fetches information for a lbaas_pool."""
        return self.get(self.lbaas_pool_path % (lbaas_pool),
                        params=_params)

    @APIParamsCall
    def create_lbaas_pool(self, body=None):
        """Creates a new lbaas_pool."""
        return self.post(self.lbaas_pools_path, body=body)

    @APIParamsCall
    def update_lbaas_pool(self, lbaas_pool, body=None):
        """Updates a lbaas_pool."""
        return self.put(self.lbaas_pool_path % (lbaas_pool),
                        body=body)

    @APIParamsCall
    def delete_lbaas_pool(self, lbaas_pool):
        """Deletes the specified lbaas_pool."""
        return self.delete(self.lbaas_pool_path % (lbaas_pool))

    @APIParamsCall
    def list_lbaas_healthmonitors(self, retrieve_all=True, **_params):
        """Fetches a list of all lbaas_healthmonitors for a tenant."""
        return self.list('healthmonitors', self.lbaas_healthmonitors_path,
                         retrieve_all, **_params)

    @APIParamsCall
    def show_lbaas_healthmonitor(self, lbaas_healthmonitor, **_params):
        """Fetches information for a lbaas_healthmonitor."""
        return self.get(self.lbaas_healthmonitor_path % (lbaas_healthmonitor),
                        params=_params)

    @APIParamsCall
    def create_lbaas_healthmonitor(self, body=None):
        """Creates a new lbaas_healthmonitor."""
        return self.post(self.lbaas_healthmonitors_path, body=body)

    @APIParamsCall
    def update_lbaas_healthmonitor(self, lbaas_healthmonitor, body=None):
        """Updates a lbaas_healthmonitor."""
        return self.put(self.lbaas_healthmonitor_path % (lbaas_healthmonitor),
                        body=body)

    @APIParamsCall
    def delete_lbaas_healthmonitor(self, lbaas_healthmonitor):
        """Deletes the specified lbaas_healthmonitor."""
        return self.delete(self.lbaas_healthmonitor_path %
                           (lbaas_healthmonitor))

    @APIParamsCall
    def list_lbaas_members(self, lbaas_pool, retrieve_all=True, **_params):
        """Fetches a list of all lbaas_members for a tenant."""
        return self.list('members', self.lbaas_members_path % lbaas_pool,
                         retrieve_all, **_params)

    @APIParamsCall
    def show_lbaas_member(self, lbaas_member, lbaas_pool, **_params):
        """Fetches information of a certain lbaas_member."""
        return self.get(self.lbaas_member_path % (lbaas_pool, lbaas_member),
                        params=_params)

    @APIParamsCall
    def create_lbaas_member(self, lbaas_pool, body=None):
        """Creates an lbaas_member."""
        return self.post(self.lbaas_members_path % lbaas_pool, body=body)

    @APIParamsCall
    def update_lbaas_member(self, lbaas_member, lbaas_pool, body=None):
        """Updates a lbaas_healthmonitor."""
        return self.put(self.lbaas_member_path % (lbaas_pool, lbaas_member),
                        body=body)

    @APIParamsCall
    def delete_lbaas_member(self, lbaas_member, lbaas_pool):
        """Deletes the specified lbaas_member."""
        return self.delete(self.lbaas_member_path % (lbaas_pool, lbaas_member))

    @APIParamsCall
    def list_vips(self, retrieve_all=True, **_params):
        """Fetches a list of all load balancer vips for a tenant."""
        # Pass filters in "params" argument to do_request
        return self.list('vips', self.vips_path, retrieve_all,
                         **_params)

    @APIParamsCall
    def show_vip(self, vip, **_params):
        """Fetches information of a certain load balancer vip."""
        return self.get(self.vip_path % (vip), params=_params)

    @APIParamsCall
    def create_vip(self, body=None):
        """Creates a new load balancer vip."""
        return self.post(self.vips_path, body=body)

    @APIParamsCall
    def update_vip(self, vip, body=None):
        """Updates a load balancer vip."""
        return self.put(self.vip_path % (vip), body=body)

    @APIParamsCall
    def delete_vip(self, vip):
        """Deletes the specified load balancer vip."""
        return self.delete(self.vip_path % (vip))

    @APIParamsCall
    def list_pools(self, retrieve_all=True, **_params):
        """Fetches a list of all load balancer pools for a tenant."""
        # Pass filters in "params" argument to do_request
        return self.list('pools', self.pools_path, retrieve_all,
                         **_params)

    @APIParamsCall
    def show_pool(self, pool, **_params):
        """Fetches information of a certain load balancer pool."""
        return self.get(self.pool_path % (pool), params=_params)

    @APIParamsCall
    def create_pool(self, body=None):
        """Creates a new load balancer pool."""
        return self.post(self.pools_path, body=body)

    @APIParamsCall
    def update_pool(self, pool, body=None):
        """Updates a load balancer pool."""
        return self.put(self.pool_path % (pool), body=body)

    @APIParamsCall
    def delete_pool(self, pool):
        """Deletes the specified load balancer pool."""
        return self.delete(self.pool_path % (pool))

    @APIParamsCall
    def retrieve_pool_stats(self, pool, **_params):
        """Retrieves stats for a certain load balancer pool."""
        return self.get(self.pool_path_stats % (pool), params=_params)

    @APIParamsCall
    def list_members(self, retrieve_all=True, **_params):
        """Fetches a list of all load balancer members for a tenant."""
        # Pass filters in "params" argument to do_request
        return self.list('members', self.members_path, retrieve_all,
                         **_params)

    @APIParamsCall
    def show_member(self, member, **_params):
        """Fetches information of a certain load balancer member."""
        return self.get(self.member_path % (member), params=_params)

    @APIParamsCall
    def create_member(self, body=None):
        """Creates a new load balancer member."""
        return self.post(self.members_path, body=body)

    @APIParamsCall
    def update_member(self, member, body=None):
        """Updates a load balancer member."""
        return self.put(self.member_path % (member), body=body)

    @APIParamsCall
    def delete_member(self, member):
        """Deletes the specified load balancer member."""
        return self.delete(self.member_path % (member))

    @APIParamsCall
    def list_health_monitors(self, retrieve_all=True, **_params):
        """Fetches a list of all load balancer health monitors for a tenant."""
        # Pass filters in "params" argument to do_request
        return self.list('health_monitors', self.health_monitors_path,
                         retrieve_all, **_params)

    @APIParamsCall
    def show_health_monitor(self, health_monitor, **_params):
        """Fetches information of a certain load balancer health monitor."""
        return self.get(self.health_monitor_path % (health_monitor),
                        params=_params)

    @APIParamsCall
    def create_health_monitor(self, body=None):
        """Creates a new load balancer health monitor."""
        return self.post(self.health_monitors_path, body=body)

    @APIParamsCall
    def update_health_monitor(self, health_monitor, body=None):
        """Updates a load balancer health monitor."""
        return self.put(self.health_monitor_path % (health_monitor), body=body)

    @APIParamsCall
    def delete_health_monitor(self, health_monitor):
        """Deletes the specified load balancer health monitor."""
        return self.delete(self.health_monitor_path % (health_monitor))

    @APIParamsCall
    def associate_health_monitor(self, pool, body):
        """Associate  specified load balancer health monitor and pool."""
        return self.post(self.associate_pool_health_monitors_path % (pool),
                         body=body)

    @APIParamsCall
    def disassociate_health_monitor(self, pool, health_monitor):
        """Disassociate specified load balancer health monitor and pool."""
        path = (self.disassociate_pool_health_monitors_path %
                {'pool': pool, 'health_monitor': health_monitor})
        return self.delete(path)

    @APIParamsCall
    def create_qos_queue(self, body=None):
        """Creates a new queue."""
        return self.post(self.qos_queues_path, body=body)

    @APIParamsCall
    def list_qos_queues(self, **_params):
        """Fetches a list of all queues for a tenant."""
        return self.get(self.qos_queues_path, params=_params)

    @APIParamsCall
    def show_qos_queue(self, queue, **_params):
        """Fetches information of a certain queue."""
        return self.get(self.qos_queue_path % (queue),
                        params=_params)

    @APIParamsCall
    def delete_qos_queue(self, queue):
        """Deletes the specified queue."""
        return self.delete(self.qos_queue_path % (queue))

    @APIParamsCall
    def create_agent(self, body=None):
        """Creates a new agent."""
        return self.post(self.agents_path, body=body)

    @APIParamsCall
    def list_agents(self, **_params):
        """Fetches agents."""
        # Pass filters in "params" argument to do_request
        return self.get(self.agents_path, params=_params)

    @APIParamsCall
    def show_agent(self, agent, **_params):
        """Fetches information of a certain agent."""
        return self.get(self.agent_path % (agent), params=_params)

    @APIParamsCall
    def update_agent(self, agent, body=None):
        """Updates an agent."""
        return self.put(self.agent_path % (agent), body=body)

    @APIParamsCall
    def delete_agent(self, agent):
        """Deletes the specified agent."""
        return self.delete(self.agent_path % (agent))

    @APIParamsCall
    def list_network_gateways(self, **_params):
        """Retrieve network gateways."""
        return self.get(self.network_gateways_path, params=_params)

    @APIParamsCall
    def show_network_gateway(self, gateway_id, **_params):
        """Fetch a network gateway."""
        return self.get(self.network_gateway_path % gateway_id, params=_params)

    @APIParamsCall
    def create_network_gateway(self, body=None):
        """Create a new network gateway."""
        return self.post(self.network_gateways_path, body=body)

    @APIParamsCall
    def update_network_gateway(self, gateway_id, body=None):
        """Update a network gateway."""
        return self.put(self.network_gateway_path % gateway_id, body=body)

    @APIParamsCall
    def delete_network_gateway(self, gateway_id):
        """Delete the specified network gateway."""
        return self.delete(self.network_gateway_path % gateway_id)

    @APIParamsCall
    def connect_network_gateway(self, gateway_id, body=None):
        """Connect a network gateway to the specified network."""
        base_uri = self.network_gateway_path % gateway_id
        return self.put("%s/connect_network" % base_uri, body=body)

    @APIParamsCall
    def disconnect_network_gateway(self, gateway_id, body=None):
        """Disconnect a network from the specified gateway."""
        base_uri = self.network_gateway_path % gateway_id
        return self.put("%s/disconnect_network" % base_uri, body=body)

    @APIParamsCall
    def list_dhcp_agent_hosting_networks(self, network, **_params):
        """Fetches a list of dhcp agents hosting a network."""
        return self.get((self.network_path + self.DHCP_AGENTS) % network,
                        params=_params)

    @APIParamsCall
    def list_networks_on_dhcp_agent(self, dhcp_agent, **_params):
        """Fetches a list of dhcp agents hosting a network."""
        return self.get((self.agent_path + self.DHCP_NETS) % dhcp_agent,
                        params=_params)

    @APIParamsCall
    def add_network_to_dhcp_agent(self, dhcp_agent, body=None):
        """Adds a network to dhcp agent."""
        return self.post((self.agent_path + self.DHCP_NETS) % dhcp_agent,
                         body=body)

    @APIParamsCall
    def remove_network_from_dhcp_agent(self, dhcp_agent, network_id):
        """Remove a network from dhcp agent."""
        return self.delete((self.agent_path + self.DHCP_NETS + "/%s") % (
            dhcp_agent, network_id))

    @APIParamsCall
    def list_l3_agent_hosting_routers(self, router, **_params):
        """Fetches a list of L3 agents hosting a router."""
        return self.get((self.router_path + self.L3_AGENTS) % router,
                        params=_params)

    @APIParamsCall
    def list_routers_on_l3_agent(self, l3_agent, **_params):
        """Fetches a list of L3 agents hosting a router."""
        return self.get((self.agent_path + self.L3_ROUTERS) % l3_agent,
                        params=_params)

    @APIParamsCall
    def add_router_to_l3_agent(self, l3_agent, body):
        """Adds a router to L3 agent."""
        return self.post((self.agent_path + self.L3_ROUTERS) % l3_agent,
                         body=body)

    @APIParamsCall
    def list_firewall_rules(self, retrieve_all=True, **_params):
        """Fetches a list of all firewall rules for a tenant."""
        # Pass filters in "params" argument to do_request

        return self.list('firewall_rules', self.firewall_rules_path,
                         retrieve_all, **_params)

    @APIParamsCall
    def show_firewall_rule(self, firewall_rule, **_params):
        """Fetches information of a certain firewall rule."""
        return self.get(self.firewall_rule_path % (firewall_rule),
                        params=_params)

    @APIParamsCall
    def create_firewall_rule(self, body=None):
        """Creates a new firewall rule."""
        return self.post(self.firewall_rules_path, body=body)

    @APIParamsCall
    def update_firewall_rule(self, firewall_rule, body=None):
        """Updates a firewall rule."""
        return self.put(self.firewall_rule_path % (firewall_rule), body=body)

    @APIParamsCall
    def delete_firewall_rule(self, firewall_rule):
        """Deletes the specified firewall rule."""
        return self.delete(self.firewall_rule_path % (firewall_rule))

    @APIParamsCall
    def list_firewall_policies(self, retrieve_all=True, **_params):
        """Fetches a list of all firewall policies for a tenant."""
        # Pass filters in "params" argument to do_request

        return self.list('firewall_policies', self.firewall_policies_path,
                         retrieve_all, **_params)

    @APIParamsCall
    def show_firewall_policy(self, firewall_policy, **_params):
        """Fetches information of a certain firewall policy."""
        return self.get(self.firewall_policy_path % (firewall_policy),
                        params=_params)

    @APIParamsCall
    def create_firewall_policy(self, body=None):
        """Creates a new firewall policy."""
        return self.post(self.firewall_policies_path, body=body)

    @APIParamsCall
    def update_firewall_policy(self, firewall_policy, body=None):
        """Updates a firewall policy."""
        return self.put(self.firewall_policy_path % (firewall_policy),
                        body=body)

    @APIParamsCall
    def delete_firewall_policy(self, firewall_policy):
        """Deletes the specified firewall policy."""
        return self.delete(self.firewall_policy_path % (firewall_policy))

    @APIParamsCall
    def firewall_policy_insert_rule(self, firewall_policy, body=None):
        """Inserts specified rule into firewall policy."""
        return self.put(self.firewall_policy_insert_path % (firewall_policy),
                        body=body)

    @APIParamsCall
    def firewall_policy_remove_rule(self, firewall_policy, body=None):
        """Removes specified rule from firewall policy."""
        return self.put(self.firewall_policy_remove_path % (firewall_policy),
                        body=body)

    @APIParamsCall
    def list_firewalls(self, retrieve_all=True, **_params):
        """Fetches a list of all firewals for a tenant."""
        # Pass filters in "params" argument to do_request

        return self.list('firewalls', self.firewalls_path, retrieve_all,
                         **_params)

    @APIParamsCall
    def show_firewall(self, firewall, **_params):
        """Fetches information of a certain firewall."""
        return self.get(self.firewall_path % (firewall), params=_params)

    @APIParamsCall
    def create_firewall(self, body=None):
        """Creates a new firewall."""
        return self.post(self.firewalls_path, body=body)

    @APIParamsCall
    def update_firewall(self, firewall, body=None):
        """Updates a firewall."""
        return self.put(self.firewall_path % (firewall), body=body)

    @APIParamsCall
    def delete_firewall(self, firewall):
        """Deletes the specified firewall."""
        return self.delete(self.firewall_path % (firewall))

    @APIParamsCall
    def remove_router_from_l3_agent(self, l3_agent, router_id):
        """Remove a router from l3 agent."""
        return self.delete((self.agent_path + self.L3_ROUTERS + "/%s") % (
            l3_agent, router_id))

    @APIParamsCall
    def get_lbaas_agent_hosting_pool(self, pool, **_params):
        """Fetches a loadbalancer agent hosting a pool."""
        return self.get((self.pool_path + self.LOADBALANCER_AGENT) % pool,
                        params=_params)

    @APIParamsCall
    def list_pools_on_lbaas_agent(self, lbaas_agent, **_params):
        """Fetches a list of pools hosted by the loadbalancer agent."""
        return self.get((self.agent_path + self.LOADBALANCER_POOLS) %
                        lbaas_agent, params=_params)

    @APIParamsCall
    def list_service_providers(self, retrieve_all=True, **_params):
        """Fetches service providers."""
        # Pass filters in "params" argument to do_request
        return self.list('service_providers', self.service_providers_path,
                         retrieve_all, **_params)

    def list_credentials(self, **_params):
        """Fetch a list of all credentials for a tenant."""
        return self.get(self.credentials_path, params=_params)

    @APIParamsCall
    def show_credential(self, credential, **_params):
        """Fetch a credential."""
        return self.get(self.credential_path % (credential), params=_params)

    @APIParamsCall
    def create_credential(self, body=None):
        """Create a new credential."""
        return self.post(self.credentials_path, body=body)

    @APIParamsCall
    def update_credential(self, credential, body=None):
        """Update a credential."""
        return self.put(self.credential_path % (credential), body=body)

    @APIParamsCall
    def delete_credential(self, credential):
        """Delete the specified credential."""
        return self.delete(self.credential_path % (credential))

    def list_network_profile_bindings(self, **params):
        """Fetch a list of all tenants associated for a network profile."""
        return self.get(self.network_profile_bindings_path, params=params)

    @APIParamsCall
    def list_network_profiles(self, **params):
        """Fetch a list of all network profiles for a tenant."""
        return self.get(self.network_profiles_path, params=params)

    @APIParamsCall
    def show_network_profile(self, profile, **params):
        """Fetch a network profile."""
        return self.get(self.network_profile_path % (profile), params=params)

    @APIParamsCall
    def create_network_profile(self, body=None):
        """Create a network profile."""
        return self.post(self.network_profiles_path, body=body)

    @APIParamsCall
    def update_network_profile(self, profile, body=None):
        """Update a network profile."""
        return self.put(self.network_profile_path % (profile), body=body)

    @APIParamsCall
    def delete_network_profile(self, profile):
        """Delete the network profile."""
        return self.delete(self.network_profile_path % profile)

    @APIParamsCall
    def list_policy_profile_bindings(self, **params):
        """Fetch a list of all tenants associated for a policy profile."""
        return self.get(self.policy_profile_bindings_path, params=params)

    @APIParamsCall
    def list_policy_profiles(self, **params):
        """Fetch a list of all network profiles for a tenant."""
        return self.get(self.policy_profiles_path, params=params)

    @APIParamsCall
    def show_policy_profile(self, profile, **params):
        """Fetch a network profile."""
        return self.get(self.policy_profile_path % (profile), params=params)

    @APIParamsCall
    def update_policy_profile(self, profile, body=None):
        """Update a policy profile."""
        return self.put(self.policy_profile_path % (profile), body=body)

    @APIParamsCall
    def create_metering_label(self, body=None):
        """Creates a metering label."""
        return self.post(self.metering_labels_path, body=body)

    @APIParamsCall
    def delete_metering_label(self, label):
        """Deletes the specified metering label."""
        return self.delete(self.metering_label_path % (label))

    @APIParamsCall
    def list_metering_labels(self, retrieve_all=True, **_params):
        """Fetches a list of all metering labels for a tenant."""
        return self.list('metering_labels', self.metering_labels_path,
                         retrieve_all, **_params)

    @APIParamsCall
    def show_metering_label(self, metering_label, **_params):
        """Fetches information of a certain metering label."""
        return self.get(self.metering_label_path %
                        (metering_label), params=_params)

    @APIParamsCall
    def create_metering_label_rule(self, body=None):
        """Creates a metering label rule."""
        return self.post(self.metering_label_rules_path, body=body)

    @APIParamsCall
    def delete_metering_label_rule(self, rule):
        """Deletes the specified metering label rule."""
        return self.delete(self.metering_label_rule_path % (rule))

    @APIParamsCall
    def list_metering_label_rules(self, retrieve_all=True, **_params):
        """Fetches a list of all metering label rules for a label."""
        return self.list('metering_label_rules',
                         self.metering_label_rules_path, retrieve_all,
                         **_params)

    @APIParamsCall
    def show_metering_label_rule(self, metering_label_rule, **_params):
        """Fetches information of a certain metering label rule."""
        return self.get(self.metering_label_rule_path %
                        (metering_label_rule), params=_params)

    @APIParamsCall
    def list_tunnels(self, retrieve_all=True, **_params):
        """Fetches a list of all configured tunnels for a tenant."""
        return self.list('tunnels', self.tunnels_path, retrieve_all,
                         **_params)

    @APIParamsCall
    def show_tunnel(self, tunnel, **_params):
        """Fetches information of a specific tunnel."""
        return self.get(self.tunnel_path % (tunnel), params=_params)

    @APIParamsCall
    def create_tunnel(self, body=None):
        """Creates a new tunnel."""
        return self.post(self.tunnels_path, body=body)

    @APIParamsCall
    def update_tunnel(self, tunnel, body=None):
        """Updates a tunnel."""
        return self.put(self.tunnel_path % (tunnel), body=body)

    @APIParamsCall
    def delete_tunnel(self, tunnel):
        """Deletes the specified tunnel."""
        return self.delete(self.tunnel_path % (tunnel))

    @APIParamsCall
    def list_tunnel_connections(self, retrieve_all=True, **_params):
        """Fetches all configured tunnelConnections for a tenant."""
        return self.list('tunnel_connections',
                         self.tunnel_connections_path,
                         retrieve_all,
                         **_params)

    @APIParamsCall
    def show_tunnel_connection(self, tunnel_conn, **_params):
        """Fetches information of a specific tunnelConnection."""
        return self.get(
            self.tunnel_connection_path % (tunnel_conn), params=_params
        )

    @APIParamsCall
    def create_tunnel_connection(self, body=None):
        """Creates a new tunnelConnection."""
        return self.post(self.tunnel_connections_path, body=body)

    @APIParamsCall
    def update_tunnel_connection(self, tunnel_conn, body=None):
        """Updates an tunnelConnection."""
        return self.put(
            self.tunnel_connection_path % (tunnel_conn), body=body
        )

    @APIParamsCall
    def delete_tunnel_connection(self, tunnel_conn):
        """Deletes the specified tunnelConnection."""
        return self.delete(self.tunnel_connection_path % (tunnel_conn))

    @APIParamsCall
    def list_target_networks(self, retrieve_all=True, **_params):
        """Fetches a list of all configured Target Networks for a tenant."""
        return self.list('target_networks', self.target_networks_path, retrieve_all,
                         **_params)

    @APIParamsCall
    def show_target_network(self, target_network, **_params):
        """Fetches information of a specific target_network."""
        return self.get(self.target_network_path % (target_network), params=_params)

    @APIParamsCall
    def create_target_network(self, body=None):
        """Creates a new target_network."""
        return self.post(self.target_networks_path, body=body)

    @APIParamsCall
    def update_target_network(self, target_network, body=None):
        """Updates an target_network."""
        return self.put(self.target_network_path % (target_network), body=body)

    @APIParamsCall
    def delete_target_network(self, target_network):
        """Deletes the specified target_network."""
        return self.delete(self.target_network_path % (target_network))

    def __init__(self, **kwargs):
        """Initialize a new client for the Neutron v2.0 API."""
        super(Client, self).__init__()
        self.httpclient = client.HTTPClient(**kwargs)
        self.version = '2.0'
        self.format = 'json'
        self.action_prefix = "/v%s" % (self.version)
        self.retries = 0
        self.retry_interval = 1

    def _handle_fault_response(self, status_code, response_body):
        # Create exception with HTTP status code and message
        _logger.debug(_("Error message: %s"), response_body)
        # Add deserialized error message to exception arguments
        try:
            des_error_body = self.deserialize(response_body, status_code)
        except Exception:
            # If unable to deserialized body it is probably not a
            # Neutron error
            des_error_body = {'message': response_body}
        # Raise the appropriate exception
        exception_handler_v20(status_code, des_error_body)

    def _check_uri_length(self, action):
        uri_len = len(self.httpclient.endpoint_url) + len(action)
        if uri_len > self.MAX_URI_LEN:
            raise exceptions.RequestURITooLong(
                excess=uri_len - self.MAX_URI_LEN)

    def do_request(self, method, action, body=None, headers=None, params=None):
        # Add format and tenant_id
        action += ".%s" % self.format
        action = self.action_prefix + action
        if type(params) is dict and params:
            params = utils.safe_encode_dict(params)
            action += '?' + urllib.urlencode(params, doseq=1)
        # Ensure client always has correct uri - do not guesstimate anything
        self.httpclient.authenticate_and_fetch_endpoint_url()
        self._check_uri_length(action)

        if body:
            body = self.serialize(body)
        self.httpclient.content_type = self.content_type()
        resp, replybody = self.httpclient.do_request(action, method, body=body)
        status_code = self.get_status_code(resp)
        if status_code in (httplib.OK,
                           httplib.CREATED,
                           httplib.ACCEPTED,
                           httplib.NO_CONTENT):
            return self.deserialize(replybody, status_code)
        else:
            self._handle_fault_response(status_code, replybody)

    def get_auth_info(self):
        return self.httpclient.get_auth_info()

    def get_status_code(self, response):
        """Returns the integer status code from the response.

        Either a Webob.Response (used in testing) or httplib.Response
        is returned.
        """
        if hasattr(response, 'status_int'):
            return response.status_int
        else:
            return response.status

    def serialize(self, data):
        """Serializes a dictionary into either xml or json.

        A dictionary with a single key can be passed and
        it can contain any structure.
        """
        if data is None:
            return None
        elif type(data) is dict:
            return serializer.Serializer(
                self.get_attr_metadata()).serialize(data, self.content_type())
        else:
            raise Exception(_("Unable to serialize object of type = '%s'") %
                            type(data))

    def deserialize(self, data, status_code):
        """Deserializes an xml or json string into a dictionary."""
        if status_code == 204:
            return data
        return serializer.Serializer(self.get_attr_metadata()).deserialize(
            data, self.content_type())['body']

    def content_type(self, _format=None):
        """Returns the mime-type for either 'xml' or 'json'.

        Defaults to the currently set format.
        """
        _format = _format or self.format
        return "application/%s" % (_format)

    def retry_request(self, method, action, body=None,
                      headers=None, params=None):
        """Call do_request with the default retry configuration.

        Only idempotent requests should retry failed connection attempts.
        :raises: ConnectionFailed if the maximum # of retries is exceeded
        """
        max_attempts = self.retries + 1
        for i in range(max_attempts):
            try:
                return self.do_request(method, action, body=body,
                                       headers=headers, params=params)
            except exceptions.ConnectionFailed:
                # Exception has already been logged by do_request()
                if i < self.retries:
                    _logger.debug(_('Retrying connection to Neutron service'))
                    time.sleep(self.retry_interval)
                else:
                    raise

        raise exceptions.ConnectionFailed(reason=_("Maximum attempts reached"))

    def delete(self, action, body=None, headers=None, params=None):
        return self.retry_request("DELETE", action, body=body,
                                  headers=headers, params=params)

    def get(self, action, body=None, headers=None, params=None):
        return self.retry_request("GET", action, body=body,
                                  headers=headers, params=params)

    def post(self, action, body=None, headers=None, params=None):
        # Do not retry POST requests to avoid the orphan objects problem.
        return self.do_request("POST", action, body=body,
                               headers=headers, params=params)

    def put(self, action, body=None, headers=None, params=None):
        return self.retry_request("PUT", action, body=body,
                                  headers=headers, params=params)

    def list(self, collection, path, retrieve_all=True, **params):
        if retrieve_all:
            res = []
            for r in self._pagination(collection, path, **params):
                res.extend(r[collection])
            return {collection: res}
        else:
            return self._pagination(collection, path, **params)

    def _pagination(self, collection, path, **params):
        if params.get('page_reverse', False):
            linkrel = 'previous'
        else:
            linkrel = 'next'
        next = True
        while next:
            res = self.get(path, params=params)
            yield res
            next = False
            try:
                for link in res['%s_links' % collection]:
                    if link['rel'] == linkrel:
                        query_str = urlparse.urlparse(link['href']).query
                        params = urlparse.parse_qs(query_str)
                        next = True
                        break
            except KeyError:
                break

    @APIParamsCall
    def retrieve_loadbalancer_stats(self, loadbalancer, **_params):
        """Retrieves stats for a certain load balancer."""
        return self.get(self.lbaas_stats_path % (loadbalancer), params=_params)

    @APIParamsCall
    def list_tlscertificates(self, retrieve_all=True, **_params):
        """Fetches a list of all tlscertificates for a tenant."""
        return self.list('tlscertificates', self.lbaas_tlscertificates_path,
                         retrieve_all, **_params)

    @APIParamsCall
    def show_tlscertificates(self, tlscertificate_id, **_params):
        """Fetches information for a tlscertificate."""
        return self.get(self.lbaas_tlscertificate_path % (tlscertificate_id),
                        params=_params)

    @APIParamsCall
    def create_tlscertificate(self, body=None):
        """Creates a new tlscertificate."""
        return self.post(self.lbaas_tlscertificates_path, body=body)

    @APIParamsCall
    def update_tlscertificate(self, tlscertificate_id, body=None):
        """Updates a tlscertificate."""
        return self.put(self.lbaas_tlscertificate_path % (tlscertificate_id),
                        body=body)

    @APIParamsCall
    def delete_tlscertificate(self, tlscertificate_id):
        """Deletes the specified tlscertificate."""
        return self.delete(self.lbaas_tlscertificate_path %
                           (tlscertificate_id))

    @APIParamsCall
    def list_device_templates(self, retrieve_all=True, **_params):
        return self.list('device_templates', self.device_templates_path,
                         retrieve_all, **_params)

    @APIParamsCall
    def show_device_template(self, device_template, **_params):
        return self.get(self.device_template_path % device_template,
                        params=_params)

    @APIParamsCall
    def update_device_template(self, device_template, body=None):
        return self.put(self.device_template_path % device_template, body=body)


    @APIParamsCall
    def create_device_template(self, body=None):
        return self.post(self.device_templates_path, body=body)

    @APIParamsCall
    def delete_device_template(self, device_template):
        return self.delete(self.device_template_path % device_template)

    @APIParamsCall
    def list_devices(self, retrieve_all=True, **_params):
        return self.list('devices', self.devices_path, retrieve_all, **_params)

    @APIParamsCall
    def show_device(self, device, **_params):
        return self.get(self.device_path % device, params=_params)

    @APIParamsCall
    def update_device(self, device, body=None):
        return self.put(self.device_path % device, body=body)

    @APIParamsCall
    def create_device(self, body=None):
        return self.post(self.devices_path, body=body)

    @APIParamsCall
    def delete_device(self, device):
        return self.delete(self.device_path % device)

    @APIParamsCall
    def attach_interface(self, device, body=None):
        return self.put(self.attach_interface_path % device, body)

    @APIParamsCall
    def detach_interface(self, device, body=None):
        return self.put(self.detach_interface_path % device, body)

    @APIParamsCall
    def list_service_instances(self, retrieve_all=True, **_params):
        return self.list('service_instances', self.service_instances_path,
                         retrieve_all, **_params)

    @APIParamsCall
    def show_service_instance(self, service_instance, **_params):
        return self.get(self.service_instance_path % service_instance,
                        params=_params)

    @APIParamsCall
    def update_service_instance(self, service_instance, body=None):
        return self.put(self.service_instance_path % service_instance, body=body)


    @APIParamsCall
    def create_service_instance(self, body=None):
        return self.post(self.service_instances_path, body=body)

    @APIParamsCall
    def delete_service_instance(self, service_instance):
        return self.delete(self.service_instance_path % service_instance)

    @APIParamsCall
    def list_service_types(self, retrieve_all=True, **_params):
        return self.list('service_types', self.service_type_path,
                         retrieve_all, **_params)

    # VNFD
    _DEVICE_TEMPLATE = "device_template"
    _VNFD = "vnfd"

    @APIParamsCall
    def list_vnfds(self, retrieve_all=True, **_params):
        ret = self.list_device_templates(retrieve_all, **_params)
        return {self._VNFD + 's': ret[self._DEVICE_TEMPLATE + 's']}

    def show_vnfd(self, vnfd, **_params):
        ret = self.show_device_template(vnfd, **_params)
        return {self._VNFD: ret[self._DEVICE_TEMPLATE]}

    @APIParamsCall
    def create_vnfd(self, body=None):
        # e.g.
        # body = {'vnfd': {'vnfd': 'yaml vnfd definition strings...'}}
        if body is not None:
            args = body[self._VNFD]

            args_ = {
                'service_types': [{'service_type': 'vnfd'}],
                'infra_driver': 'heat',
                'mgmt_driver': 'noop',
            }
            KEY_LIST = ('name', 'description')
            args_.update(dict((key, args[key])
                              for key in KEY_LIST if key in args))
            body_ = {self._DEVICE_TEMPLATE: args_}
            if 'vnfd' in args:
                args_['attributes'] = {'vnfd': args['vnfd']}
        else:
            body_ = None

        ret = self.create_device_template(body_)
        return {self._VNFD: ret[self._DEVICE_TEMPLATE]}

    @APIParamsCall
    def delete_vnfd(self, vnfd):
        return self.delete_device_template(vnfd)
    # vnf
    _DEVICE = "device"
    _VNF = "vnf"

    @APIParamsCall
    def list_vnfs(self, retrieve_all=True, **_params):
        ret = self.list_devices(retrieve_all, **_params)
        return {self._VNF + 's': ret[self._DEVICE + 's']}

    @APIParamsCall
    def show_vnf(self, vnf, **_params):
        ret = self.show_device(vnf, **_params)
        return {self._VNF: ret[self._DEVICE]}

    @APIParamsCall
    def create_vnf(self, body=None):
        arg = body[self._VNF]
        arg_ = {
            'template_id': arg['vnfd_id'],
        }
        for key in ('tenant_id', 'name'):
            if key in arg:
                arg_[key] = arg[key]
        if 'config' in arg:
            arg_['attributes'] = {'config': arg['config']}
        body_ = {self._DEVICE: arg_}
        ret = self.create_device(body_)
        return {self._VNF: ret[self._DEVICE]}

    @APIParamsCall
    def delete_vnf(self, vnf):
        return self.delete_device(vnf)

    @APIParamsCall
    def update_vnf(self, vnf, body=None):
        args = body[self._VNF]
        args_ = {}
        if 'config' in args:
            args_['attributes'] = {'config': args['config']}
        body_ = {self._DEVICE: args_}
        ret = self.update_device(vnf, body_)
        return {self._VNF: ret[self._DEVICE]}

