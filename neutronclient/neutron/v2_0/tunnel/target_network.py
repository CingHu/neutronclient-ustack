#    (c) Copyright 2015 UnitedStack.
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

from neutronclient.common import utils
from neutronclient.neutron import v2_0 as neutronv20
from neutronclient.openstack.common.gettextutils import _


class ListTargetNetwork(neutronv20.ListCommand):
    """List TargetNetworks that belong to a tenant."""

    resource = 'target_network'
    log = logging.getLogger(__name__ + '.ListTargetNetwork')
    list_columns = ['id', 'network_cidr', 'tunnel_id']
    _formatters = {}
    pagination_support = True
    sorting_support = True


class ShowTargetNetwork(neutronv20.ShowCommand):
    """Show information of a given TargetNetwork."""

    resource = 'target_network'
    log = logging.getLogger(__name__ + '.ShowTargetNetwork')


class CreateTargetNetwork(neutronv20.CreateCommand):
    """Create an TargetNetwork."""

    resource = 'target_network'
    log = logging.getLogger(__name__ + '.CreateTargetNetwork')

    def add_known_arguments(self, parser):
        parser.add_argument(
            '--tunnel_id',
            required=True,
            help=_('Tunnel id'))
        parser.add_argument(
            '--network_cidr',
            required=True,
            help=_('network_cidr'))

    def args2body(self, parsed_args):
        _tunnel_id = neutronv20.find_resourceid_by_name_or_id(
            self.get_client(), 'tunnel',
            parsed_args.tunnel_id)
        body = {'target_network': {
            'tunnel_id': _tunnel_id,
            'network_cidr':parsed_args.network_cidr,
        }, }
        if parsed_args.tunnel_id:
            body['target_network'].update({'tunnel_id': parsed_args.tunnel_id})
        if parsed_args.network_cidr:
            body['target_network'].update({
                'network_cidr': parsed_args.network_cidr})
        return body


class UpdateTargetNetwork(neutronv20.UpdateCommand):
    """Update a given Target Network."""

    resource = 'target_network'
    log = logging.getLogger(__name__ + '.UpdateTargetNetwork')

    def add_known_arguments(self, parser):
        parser.add_argument(
            '--tunnel_id',
            required=True,
            help=_('Tunnel id'))
        parser.add_argument(
            '--network_cidr',
            required=True,
            help=_('network_cidr'))

    def args2body(self, parsed_args):
        _tunnel_id = neutronv20.find_resourceid_by_name_or_id(
            self.get_client(), 'tunnel',
            parsed_args.tunnel_id)
        body = {'target_network': {
            'tunnel_id': _tunnel_id,
            'network_cidr':parsed_args.network_cidr,
        }, }
        return body


class DeleteTargetNetwork(neutronv20.DeleteCommand):
    """Delete a given Target Network."""

    resource = 'target_network'
    log = logging.getLogger(__name__ + '.DeleteTargetNetwork')
