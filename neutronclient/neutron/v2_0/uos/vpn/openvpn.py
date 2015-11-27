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

import logging

from neutronclient.neutron import v2_0 as neutronV20
from neutronclient.openstack.common.gettextutils import _


class ListOpenVPN(neutronV20.ListCommand):
    """List openvpns that belong to a given tenant."""

    resource = 'openvpnconnection'
    log = logging.getLogger(__name__ + '.ListOpenVPN')
    list_columns = ['id', 'name', 'peer_cidr', 'protocol','port', 'created_at']
    pagination_support = True
    sorting_support = True


class ShowOpenVPN(neutronV20.ShowCommand):
    """Show openvpn information."""

    resource = 'openvpnconnection'
    log = logging.getLogger(__name__ + '.ShowOpenVPN')


class CreateOpenVPN(neutronV20.CreateCommand):
    """Create a openvpn for a given tenant."""

    resource = 'openvpnconnection'
    log = logging.getLogger(__name__ + '.CreateOpenVPN')

    def add_known_arguments(self, parser):
        parser.add_argument(
            'name',
            help=_('Name of this openvpn'))
        parser.add_argument(
            'peer_cidr',
            help=_('CIDR of the openvpn client'))
        parser.add_argument(
            'port',
            help=_('port of the openvpn'))
        parser.add_argument(
            'protocol',
            help=_('protocol of the openvpn, UDP or TCP'))
        parser.add_argument(
            'router_id',
            help=_('router of the openvpn'))
        parser.add_argument(
            '--description',
            help=_('Descrition of the openvpn'))

    def args2body(self, parsed_args):
        _router_id = neutronV20.find_resourceid_by_name_or_id(
            self.get_client(), 'router', parsed_args.router_id)
        body = {'openvpnconnection': {'name': parsed_args.name,
                                   'peer_cidr': parsed_args.peer_cidr,
                                   'port': parsed_args.port,
                                   'protocol': parsed_args.protocol,
                                   'router_id': _router_id, }, }

        if parsed_args.description:
            body['openvpnconnection'].update(
                {'description': parsed_args.description})
        if parsed_args.tenant_id:
            body['openvpnconnection'].update(
                {'tenant_id': parsed_args.tenant_id})

        return body


class DeleteOpenVPN(neutronV20.DeleteCommand):
    """Delete a given openvpn."""

    resource = 'openvpnconnection'
    log = logging.getLogger(__name__ + '.DeleteOpenVPN')

class UpdateOpenVPNMixin(object):
    def add_arguments_port(self, parser):
        group_sg = parser.add_mutually_exclusive_group()
        group_sg.add_argument(
            '--security-group', metavar='SECURITY_GROUP',
            default=[], action='append', dest='security_groups',
            help=_('Security group associated with the port '
            '(This option can be repeated)'))
        group_sg.add_argument(
            '--no-security-groups',
            action='store_true',
            help=_('Associate no security groups with the port'))

    def _resolv_sgid(self, secgroup):
        return neutronV20.find_resourceid_by_name_or_id(
            self.get_client(), 'security_group', secgroup)

    def args2body_secgroup(self, parsed_args, port):
        if parsed_args.security_groups:
            port['security_groups'] = [self._resolv_sgid(sg) for sg
                                       in parsed_args.security_groups]
        elif parsed_args.no_security_groups:
            port['security_groups'] = []

class UpdateOpenVPN(neutronV20.UpdateCommand):
    """Update openvpn's information."""

    resource = 'openvpnconnection'
    log = logging.getLogger(__name__ + '.UpdateOpenVPN')

