# Copyright 2014 OpenStack Foundation.
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

import logging
from neutronclient.v2_0 import APIParamsCall
from neutronclient.common import exceptions

LOG = logging.getLogger(__name__)

class UosClientMixin(object):
    vpnusers_path = "/vpn/vpnusers"
    vpnuser_path = "/vpn/vpnusers/%s"
    pptpconnections_path = "/vpn/pptpconnections"
    pptpconnection_path = "/vpn/pptpconnections/%s"
    openvpnconnections_path = "/vpn/openvpnconnections"
    openvpnconnection_path = "/vpn/openvpnconnections/%s"
    uos_resources = '/uos_resources'
    uos_resource = '/uos_resources/%s'
    add_portforwarding_path = uos_resource + '/add_router_portforwarding'
    remove_portforwarding_path = uos_resource + '/remove_router_portforwarding'
    update_ratelimit_path = uos_resource + '/update_floatingip_ratelimit'
    update_registerno_path = uos_resource + '/update_floatingip_registerno'
    get_router_details_path = uos_resource + '/get_router_details'
    associate_floatingip_router_path = (uos_resource +
                                        '/associate_floatingip_router')
    swap_router_path = (uos_resource + '/swap_router')
    change_router2ha_path = (uos_resource + '/change_router_to_ha')
    change_router2nonha_path = (uos_resource + '/change_router_to_nonha')
    ping_agent_path = (uos_resource + '/ping_agent')
    get_fip_usage_path = (uos_resource + '/get_fip_usage')
    get_resource_counter_path = uos_resource + '/get_resource_counter'
    get_resource_host_counter_path = uos_resource  + '/get_resource_host_counter'

    #device_id=<uuid>&  uuid is 36
    device_id_filter_len = 47

    @APIParamsCall
    def list_uos_resources(self, **_params):
        """Fetch all resources of a tenant."""
        result = {}
        try:
            result = self.get(self.uos_resources, params=_params)
        except exceptions.RequestURITooLong as uri_len_exc:
            # (Zebra) support split one request to several requests
            # The URI is too long because of too many device_id filters
            # Use the excess attribute of the exception to know how many
            result = {}
            devices = _params.pop('device_id',[])
            if isinstance(devices, basestring):
                devices = [devices]
            device_count = len(devices)
            if device_count <= 0:
                LOG.error("device_count <=0 maybe the cause is not device_id")
                return result
            #uri_len_exc.excess is the length overload
            #so max_size is the max size for device_id for
            #the first(every) request
            if self.device_id_filter_len * device_count <= uri_len_exc.excess:
                LOG.error("maybe the cause is not device_id please check more")
                return result
            max_size = ((self.device_id_filter_len * device_count) -
                        uri_len_exc.excess)
            chunk_size = max_size / self.device_id_filter_len
            check_ids = {}
            for i in range(0, device_count, chunk_size):
                _params['device_id'] = devices[i: i + chunk_size]
                tmp = self.get(self.uos_resources, params=_params)
                # tmp is dict
                for key, value in tmp.items():
                    if key in result:
                        for _i in value:
                            if _i['id'] not in check_ids[key]:
                                result[key].append(_i)
                                check_ids[key].add(_i['id'])
                    else:
                        result[key] = value
                        check_ids[key] = set()
                        for _i in value:
                            check_ids[key].add(_i['id'])
        return result

    @APIParamsCall
    def show_router_detail(self, router_id, **_params):
        """Fetch router's details."""
        return self.get(self.get_router_details_path % (router_id),
                        params=_params)

    @APIParamsCall
    def add_router_portforwarding(self, router_id, body=None):
        """Fetch router's details."""
        return self.put(self.add_portforwarding_path % (router_id),
                        body=body)

    @APIParamsCall
    def remove_router_portforwarding(self, router_id, body=None):
        """Fetch router's details."""
        return self.put(self.remove_portforwarding_path % (router_id),
                        body=body)

    @APIParamsCall
    def update_rate_limit(self, floatingip_id, body=None):
        """update floatingip's rate limit."""
        return self.put(self.update_ratelimit_path % (floatingip_id),
                        body=body)

    @APIParamsCall
    def update_floatingip_registerno(self, floatingip_id, body=None):
        """update floatingip's registerno."""
        return self.put(self.update_registerno_path % (floatingip_id),
                        body=body)

    @APIParamsCall
    def list_vpnusers(self, retrieve_all=True, **_params):
        """Fetches a list of all vpnusers for a tenant."""
        # Pass filters in "params" argument to do_request
        return self.list('vpnusers', self.vpnusers_path, retrieve_all,
                         **_params)

    @APIParamsCall
    def show_vpnuser(self, vpnuser, **_params):
        """Fetches information of a certain vpnuser."""
        return self.get(self.vpnuser_path % (vpnuser), params=_params)

    @APIParamsCall
    def create_vpnuser(self, body=None):
        """Creates a new vpnuser."""
        return self.post(self.vpnusers_path, body=body)

    @APIParamsCall
    def update_vpnuser(self, vpnuser, body=None):
        """Updates a vpnuser."""
        return self.put(self.vpnuser_path % (vpnuser), body=body)

    @APIParamsCall
    def delete_vpnuser(self, vpnuser):
        """Deletes the specified vpnuser."""
        return self.delete(self.vpnuser_path % (vpnuser))

    @APIParamsCall
    def list_pptpconnections(self, retrieve_all=True, **_params):
        """Fetches a list of all networks for a tenant."""
        # Pass filters in "params" argument to do_request
        return self.list('pptpconnections', self.pptpconnections_path,
                         retrieve_all, **_params)

    @APIParamsCall
    def show_pptpconnection(self, pptpconnection, **_params):
        """Fetches information of a certain network."""
        return self.get(self.pptpconnection_path % (pptpconnection),
                        params=_params)

    @APIParamsCall
    def create_pptpconnection(self, body=None):
        """Creates a new pptpconnection."""
        return self.post(self.pptpconnections_path, body=body)

    @APIParamsCall
    def update_pptpconnection(self, pptpconnection, body=None):
        """Updates a pptpconnection."""
        return self.put(self.pptpconnection_path % (pptpconnection),
                        body=body)

    @APIParamsCall
    def delete_pptpconnection(self, pptpconnection):
        """Deletes the specified pptpconnection."""
        return self.delete(self.pptpconnection_path % (pptpconnection))

    @APIParamsCall
    def associate_floatingip_router(self, fip_id, body=None):
        """Associate a floatingip with a router."""
        return self.put(self.associate_floatingip_router_path % (fip_id),
                        body=body)

    @APIParamsCall
    def swap_router(self, router_id, body=None):
        """Swap router's master l3 agent."""
        return self.put(self.swap_router_path % (router_id),
                        body=body)

    @APIParamsCall
    def change_router_to_ha(self, router_id, body=None):
        """Change router into HA router."""
        return self.put(self.change_router2ha_path % (router_id),
                        body=body)

    @APIParamsCall
    def change_router_to_nonha(self, router_id, body=None):
        """Change router into non HA router."""
        return self.put(self.change_router2nonha_path % (router_id),
                        body=body)

    @APIParamsCall
    def ping_agent(self, body):
        """Ping agent."""
        return self.put(self.ping_agent_path % 'dumyid',
                        body=body)

    @APIParamsCall
    def get_fip_usages(self, **_params):
        """get fip usages."""
        return self.get(self.get_fip_usage_path % 'dumyid',
                        params=_params)

    @APIParamsCall
    def get_resource_counter(self, resource, **_params):
        """get resource counter."""
        return self.get(self.get_resource_counter_path % resource,
                        params=_params)

    @APIParamsCall
    def get_resource_host_counter(self, resource_id, **_params):
        """get list counter."""
        return self.get(self.get_resource_host_counter_path % resource_id,
                        params=_params)

    @APIParamsCall
    def list_openvpnconnections(self, retrieve_all=True, **_params):
        """Fetches a list of all networks for a tenant."""
        # Pass filters in "params" argument to do_request
        return self.list('openvpnconnections', self.openvpnconnections_path,
                         retrieve_all, **_params)

    @APIParamsCall
    def show_openvpnconnection(self, openvpnconnection, **_params):
        """Fetches information of a certain network."""
        return self.get(self.openvpnconnection_path % (openvpnconnection),
                        params=_params)

    @APIParamsCall
    def create_openvpnconnection(self, body=None):
        """Creates a new openvpnconnection."""
        return self.post(self.openvpnconnections_path, body=body)

    @APIParamsCall
    def update_openvpnconnection(self, openvpnconnection, body=None):
        """Updates a openvpnconnection."""
        return self.put(self.openvpnconnection_path % (openvpnconnection),
                        body=body)

    @APIParamsCall
    def delete_openvpnconnection(self, openvpnconnection):
        """Deletes the specified openvpnconnection."""
        return self.delete(self.openvpnconnection_path % (openvpnconnection))

