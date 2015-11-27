#    (c) Copyright 2015 UnitedStack
#    All Rights Reserved.
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
# @author: Wei Wang, UnitedStack.
#

import logging

from neutronclient.neutron import v2_0 as neutronv20
from neutronclient.openstack.common.gettextutils import _


class ListTunnel(neutronv20.ListCommand):
    """List Tunnel configurations that belong to a given tenant."""

    resource = 'tunnel'
    log = logging.getLogger(__name__ + '.ListTunnel')
    list_columns = [
        'id', 'name', 'type', 'router_id', 'status', 'local_subnet'
    ]
    _formatters = {}
    pagination_support = True
    sorting_support = True


class ShowTunnel(neutronv20.ShowCommand):
    """Show information of a given Tunnel."""

    resource = 'tunnel'
    log = logging.getLogger(__name__ + '.ShowTunnel')


class CreateTunnel(neutronv20.CreateCommand):
    """Create a Tunnel."""
    resource = 'tunnel'
    log = logging.getLogger(__name__ + '.CreateTunnel')

    def add_known_arguments(self, parser):
        parser.add_argument(
            '--admin-state-up',
            default='UP',
            help=_('Set admin state up to false'))
        parser.add_argument(
            '--name',
            help=_('Set a name for the tunnel'))
        parser.add_argument(
            'router', metavar='ROUTER',
            help=_('Router unique identifier for the tunnel'))
        parser.add_argument(
            '--type',
            help=_('Type'))
        parser.add_argument(
            '--local_subnet',
            help=_('Local Subnet'))
        parser.add_argument(
            '--mode', default='gre',
            help=_('Mode'))


    def args2body(self, parsed_args):
        try:
            _subnet_id = neutronv20.find_resourceid_by_name_or_id(
                self.get_client(), 'subnet',
                parsed_args.local_subnet)
        except TypeError:
            _subnet_id = ""
        _router_id = neutronv20.find_resourceid_by_name_or_id(
            self.get_client(), 'router',
            parsed_args.router)

        body = {self.resource: {'local_subnet': _subnet_id,
                                'router_id': _router_id,
                                'admin_state_up': parsed_args.admin_state_up,
                                'mode': parsed_args.mode,
                                'type': parsed_args.type}, }
        neutronv20.update_dict(parsed_args, body[self.resource],
                               ['name'])

        return body


class UpdateTunnel(neutronv20.UpdateCommand):
    """Update a given Tunnel."""

    resource = 'tunnel'
    log = logging.getLogger(__name__ + '.UpdateTunnel')

    def add_known_arguments(self, parser):
        parser.add_argument(
            '--admin-state-up',
            default='UP',
            help=_('Set admin state up to false'))
        parser.add_argument(
            '--name',
            help=_('Set a name for the tunnel'))
        parser.add_argument(
            'router', metavar='ROUTER',
            help=_('Router unique identifier for the tunnel'))
        parser.add_argument(
            '--type',
            help=_('Type'))
        parser.add_argument(
            '--local_subnet',
            help=_('Local Subnet'))


    def args2body(self, parsed_args):
        try:
            _subnet_id = neutronv20.find_resourceid_by_name_or_id(
                self.get_client(), 'subnet',
                parsed_args.local_subnet)
        except TypeError:
            _subnet_id = ""
        _router_id = neutronv20.find_resourceid_by_name_or_id(
            self.get_client(), 'router',
            parsed_args.router)

        body = {self.resource: {'local_subnet': _subnet_id,
                                'router_id': _router_id,
                                'admin_state_up': parsed_args.admin_state_up,
                                'type': parsed_args.type}, }
        neutronv20.update_dict(parsed_args, body[self.resource],
                               ['name'])

        return body

class DeleteTunnel(neutronv20.DeleteCommand):
    """Delete a given Tunnel."""

    resource = 'tunnel'
    log = logging.getLogger(__name__ + '.DeleteTunnel')
