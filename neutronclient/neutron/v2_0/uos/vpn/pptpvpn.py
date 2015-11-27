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


class ListVpnPptp(neutronV20.ListCommand):
    """List pptp vpns that belong to a given tenant."""

    resource = 'pptpconnection'
    log = logging.getLogger(__name__ + '.ListVpnPptp')
    list_columns = ['id', 'name', 'vpn_cidr',  'created_at']
    pagination_support = True
    sorting_support = True


class ShowVpnPptp(neutronV20.ShowCommand):
    """Show pptp vpn information."""

    resource = 'pptpconnection'
    log = logging.getLogger(__name__ + '.ShowVpnPptp')


class CreateVpnPptp(neutronV20.CreateCommand):
    """Create a pptp vpn for a given tenant."""

    resource = 'pptpconnection'
    log = logging.getLogger(__name__ + '.CreateVpnPptp')

    def add_known_arguments(self, parser):
        parser.add_argument(
            'name',
            help=_('Name of this pptp vpn'))
        parser.add_argument(
            'vpn_cidr',
            help=_('CIDR of the pptp vpn'))
        parser.add_argument(
            'router_id',
            help=_('router of the pptp vpn'))
        parser.add_argument(
            '--description',
            help=_('Descrition of the pptp vpn'))

    def args2body(self, parsed_args):
        _router_id = neutronV20.find_resourceid_by_name_or_id(
            self.get_client(), 'router', parsed_args.router_id)
        body = {'pptpconnection': {'name': parsed_args.name,
                                   'vpn_cidr': parsed_args.vpn_cidr,
                                   'router_id': _router_id, }, }

        if parsed_args.description:
            body['pptpconnection'].update(
                {'description': parsed_args.description})
        if parsed_args.tenant_id:
            body['pptpconnection'].update(
                {'tenant_id': parsed_args.tenant_id})

        return body


class DeleteVpnPptp(neutronV20.DeleteCommand):
    """Delete a given pptp vpn."""

    resource = 'pptpconnection'
    log = logging.getLogger(__name__ + '.DeleteVpnPptp')


class UpdateVpnPptp(neutronV20.UpdateCommand):
    """Update pptp vpn's information."""

    resource = 'pptpconnection'
    log = logging.getLogger(__name__ + '.UpdateVpnPptp')
