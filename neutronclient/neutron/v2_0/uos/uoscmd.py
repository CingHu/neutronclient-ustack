# Copyright 2014 OpenStack Foundation.
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
import netaddr
import argparse
import logging
import sys

from neutronclient.neutron import v2_0 as neutronV20
from neutronclient.openstack.common.gettextutils import _


class ListResources(neutronV20.ListCommand):
    """List resources that belong to a given tenant."""

    resource = 'uos_resource'
    log = logging.getLogger(__name__ + '.ListResources')
    list_columns_dict = {'networks': ['id', 'name', 'created_at'],
                         'subnets': ['id', 'name', 'cidr', 'created_at'],
                         'ports': ['id', 'name', 'mac_address', 'fixed_ips'],
                         'floatingips': ['id', 'fixed_ip_address',
                                         'floating_ip_address', 'port_id',
                                         'rate_limit'],
                         'routers': ['id', 'name', 'external_gateway_info'],
                         'security_groups': ['id', 'name', 'description'],
                         'security_group_rules': ['id', 'security_group_id',
                                                 'direction', 'protocol',
                                                 'remote_ip_prefix',
                                                 'remote_group_id'],
                         'vpnusers': ['id', 'name', 'created_at'],
                         'pptpconnections': ['id', 'name', 'created_at'],
                         'openvpnconnections': ['id', 'name','port','protocol', 'created_at'],
                         }

    def call_server(self, neutron_client, search_opts, parsed_args):
        data = super(ListResources, self).call_server(
            neutron_client, search_opts, parsed_args)
        result = {}
        if data:
            result[self.resource + "s"] = data
        return result

    def get_data(self, parsed_args):
        self.log.debug('get_data(%s)', parsed_args)
        data = self.retrieve_list(parsed_args)
        return [], data

    def produce_output(self, parsed_args, column_names, data):
        for resources in data.keys():
            sys.stdout.write('%s:\n' % resources)
            sub_data = data.get(resources)
            self.list_columns = self.list_columns_dict.get(resources)
            _colns, _data = self.setup_columns(sub_data, parsed_args)
            super(ListResources, self).produce_output(parsed_args,
                                                      _colns, _data)
        return 0

class ShowRouterInterfaceDetailWithName(neutronV20.ShowCommand):
    """Show information of a given router."""

    resource = 'router'
    log = logging.getLogger(__name__ + '.ShowRouterInterfaceDetailWithName')
    json_indent = 5

    def call_server(self, client, _id, **params):
        data = client.show_router_detail(_id, **params)
        if data:
            return {self.resource: data}
        return data

class UpdateRateLimit(neutronV20.UpdateCommand):
    """Update rate limit of a given floatingip."""

    resource = 'floatingip'
    log = logging.getLogger(__name__ + '.UpdateRateLimit')
    allow_names = False

    def add_known_arguments(self, parser):
        parser.add_argument(
            'rate_limit',
            default=1024, choices=[1024, 2048, 4096, 8192, 10240],
            type=int,
            help=_('rate limit kbps'))

    def args2body(self, parsed_args):
        body = {self.resource: {'rate_limit':  parsed_args.rate_limit}}
        return body

    def call_server(self, neutron_client, _id, body):
        neutron_client.update_rate_limit(_id, body[self.resource])


class UpdateFipRegisterNo(neutronV20.UpdateCommand):
    """Update registerno of a given floatingip."""

    resource = 'floatingip'
    log = logging.getLogger(__name__ + '.UpdateFipRegisterNo')
    allow_names = False

    def add_known_arguments(self, parser):
        parser.add_argument(
            'registerno',
            help=_('Register Number'))

    def args2body(self, parsed_args):
        body = {self.resource: {'uos_registerno': parsed_args.registerno}}
        return body

    def call_server(self, neutron_client, _id, body):
        neutron_client.update_floatingip_registerno(
            _id, body[self.resource])


class AssociateFipRouter(neutronV20.UpdateCommand):
    """Associate a floatingip with a router."""

    resource = 'floatingip'
    log = logging.getLogger(__name__ + '.AssociateFipRouter')

    def add_known_arguments(self, parser):
        parser.add_argument(
            'router',
            help=_("Router's name or ID"))

    def args2body(self, parsed_args):
        neutron_client = self.get_client()
        router_id = neutronV20.find_resourceid_by_name_or_id(
            neutron_client, 'router', parsed_args.router)
        body = {self.resource: {'router_id':  router_id}}
        return body

    def call_server(self, neutron_client, _id, body):
        neutron_client.associate_floatingip_router(_id, body[self.resource])


class SwapRouter(neutronV20.UpdateCommand):
    """Swapp router's master l3 agent."""

    resource = 'router'
    log = logging.getLogger(__name__ + '.SwapRouter')

    def args2body(self, parsed_args):
        return {self.resource: {'dumy': 1}}

    def call_server(self, neutron_client, _id, body):
        neutron_client.swap_router(_id, body)


class ChangeRouter2HA(neutronV20.UpdateCommand):
    """Change router into HA router."""

    resource = 'router'
    log = logging.getLogger(__name__ + '.ChangeRouter2HA')

    def args2body(self, parsed_args):
        return {self.resource: {'dumy': 1}}

    def call_server(self, neutron_client, _id, body):
        neutron_client.change_router_to_ha(_id, body)


class PingAgent(neutronV20.NeutronCommand):
    """Ping agent."""

    resource = 'agent'
    log = logging.getLogger(__name__ + '.PingAgent')

    def get_parser(self, prog_name):
        parser = super(PingAgent, self).get_parser(prog_name)
        parser.add_argument('topic', help=_('Topic'))
        parser.add_argument('host', help=_('Host'))

        return parser

    def run(self, parsed_args):
        self.log.debug('run(%s)', parsed_args)
        neutron_client = self.get_client()
        neutron_client.format = parsed_args.request_format
        body = self.args2body(parsed_args)
        x = self.call_server(neutron_client, body)
        print >>self.app.stdout, x
        return

    def add_known_arguments(self, parser):
        parser.add_argument('host', help=_('Host'))
        parser.add_argument('topic', help=_('Topic'))

    def args2body(self, parsed_args):
        return {self.resource: {'host': parsed_args.host,
                                'topic': parsed_args.topic}}

    def call_server(self, neutron_client, body):
        return neutron_client.ping_agent(body)


class ChangeRouter2NonHA(neutronV20.UpdateCommand):
    """Change router into non HA router."""

    resource = 'router'
    log = logging.getLogger(__name__ + '.ChangeRouter2NonHA')

    def args2body(self, parsed_args):
        return {self.resource: {'dumy': 1}}

    def call_server(self, neutron_client, _id, body):
        neutron_client.change_router_to_nonha(_id, body)


def positive_non_zero_int(text):
    if text is None:
        return None
    try:
        value = int(text)
    except ValueError:
        msg = "%s must be a int" % text
        raise argparse.ArgumentTypeError(msg)
    if value <= 0 or value >= 65535:
        msg = "%s must be greater than 0 and less than 65535" % text
        raise argparse.ArgumentTypeError(msg)
    return value


class AddPortFD(neutronV20.UpdateCommand):
    """Add a port forwarding rule to a router."""

    resource = 'router'
    log = logging.getLogger(__name__ + '.AddPortFD')

    def add_known_arguments(self, parser):
        parser.add_argument(
            '--outside_port',
            required=True,
            type=positive_non_zero_int,
            help=_('the port on the router, which is public port'))
        parser.add_argument(
            '--inside_addr',
            required=True,
            help=_('the private IP address'))
        parser.add_argument(
            '--inside_port',
            required=True,
            type=positive_non_zero_int,
            help=_('the port on the private IP address'))
        parser.add_argument(
            '--protocol',
            required=True,
            default='TCP', choices=['TCP', 'UDP'],
            help=_('the transport protocol'))

    def args2body(self, parsed_args):
        body = {self.resource: {'outside_port':  parsed_args.outside_port,
                                'inside_addr': parsed_args.inside_addr,
                                'inside_port': parsed_args.inside_port,
                                'protocol': parsed_args.protocol}}
        return body

    def call_server(self, neutron_client, _id, body):
        neutron_client.add_router_portforwarding(_id, body[self.resource])


class DelPortFD(neutronV20.UpdateCommand):
    """Delete a port forwarding rule from a router."""

    resource = 'router'
    log = logging.getLogger(__name__ + '.DelPortFD')

    def add_known_arguments(self, parser):
        parser.add_argument(
            'port_fd_id',
            help=_('the port forward ID'))

    def args2body(self, parsed_args):
        body = {self.resource: {'id':  parsed_args.port_fd_id}}
        return body

    def call_server(self, neutron_client, _id, body):
        neutron_client.remove_router_portforwarding(_id, body[self.resource])

class ResourceCounter(neutronV20.ListCommand):
    resource = 'resource'
    list_columns = ['resource','counter']
    log = logging.getLogger(__name__ + '.ResourceCounter')
    pagination_support = True
    sorting_support = True

    def get_parser(self, prog_name):
        parser = super(ResourceCounter, self).get_parser(prog_name)
        parser.add_argument(
            'resource', metavar='resource',
            help=_('name of resource statistic '))
        return parser

    def call_server(self, neutron_client, search_opts, parsed_args):
        resources = parsed_args.resource + 's'
        obj_lister = getattr(neutron_client, 'get_resource_counter')
        data = obj_lister(resources, **search_opts)
        return data

class ListCounter(neutronV20.ListCommand):
    """list counter"""

    resource = 'list'
    list_columns = ['action','id', 'counter']
    log = logging.getLogger(__name__ + '.ListCounter')
    pagination_support = True
    sorting_support = True

    def get_parser(self, prog_name):
        parser = super(ListCounter, self).get_parser(prog_name)
        parser.add_argument(
            'resource_id', metavar='RESOURCE_ID',
            help=_('if of resource, example. router, dhcp agent'))
        return parser

    def call_server(self, neutron_client, search_opts, parsed_args):
        obj_lister = getattr(neutron_client, 'get_resource_host_counter')
        data = obj_lister(parsed_args.resource_id, **search_opts)
        return data

class GetFipUsage(neutronV20.ListCommand):
    """List fip usage."""

    resource = 'fip_usage'
    list_columns = ['fip', 'subnet_name', 'used']
    unknown_parts_flag = True
    pagination_support = False
    sorting_support = False
    log = logging.getLogger(__name__ + '.GetFipUsage')

    def call_server(self, neutron_client, search_opts, parsed_args):
        data = self.get_fip_usage(neutron_client, **search_opts)
        if parsed_args.show_details:
            return data
        else:
            return {"fip_usages": []}

    def get_fip_usage(self, neutron_client, **kwargs):
        if "router:external" not in kwargs:
            kwargs['router:external'] = True
        nets = neutron_client.list_networks(**kwargs)
        nets = nets.get("networks", [])
        results = []
        used = 0
        unused = 0
        for net in nets:
            kwargs.pop('network_id', None)
            kwargs['network_id'] = net['id']
            kwargs.pop('id', None)
            if 'subnet_id' in kwargs:
                kwargs['id'] = kwargs['subnet_id']
            subnets = neutron_client.list_subnets(**kwargs)
            subnets = subnets.get("subnets", [])
            for subnet in subnets:
                if (subnet['name'] and
                    subnet['name'].startswith("ext_shadow_subnet")):
                    continue
                fips = neutron_client.list_floatingips(
                    **{"floating_subnet_id": subnet['id']})
                fips = fips.get("floatingips", [])
                fip_ips = []
                fip_map = {}
                for fip in fips:
                    fip_ips.append(fip['floating_ip_address'])
                    fip_map[fip['floating_ip_address']] = fip
                ipcidr = subnet['cidr']
                ip = netaddr.IPNetwork(ipcidr)
                num_ips = len(ip)
                allocation_pools = subnet['allocation_pools']
                for index in range(num_ips):
                    anyallo = []
                    for allo in allocation_pools:
                        start = netaddr.IPAddress(allo['start']).value
                        end = netaddr.IPAddress(allo['end']).value
                        anyallo.append(start <= ip[index].value <= end)
                    if any(anyallo):
                        if str(ip[index]) in fip_ips:
                            tenant_id = fip_map[str(ip[index])]['tenant_id']
                            results.append({"subnet_id": subnet['id'],
                                            "subnet_name": subnet['name'],
                                            "tenant_id": tenant_id,
                                            "fip": str(ip[index]),
                                            "used": "yes"})
                            used += 1
                        else:
                            results.append({"subnet_id": subnet['id'],
                                            "fip": str(ip[index]),
                                            "subnet_name": subnet['name'],
                                            "tenant_id": "",
                                            "used": "no"})
                            unused += 1
        print "Used: %s" % used
        print "Unsed: %s" % unused
        return {"fip_usages": results}
