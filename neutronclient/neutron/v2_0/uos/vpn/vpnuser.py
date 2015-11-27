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


class ListVpnUser(neutronV20.ListCommand):
    """List vpnusers that belong to a given tenant."""

    resource = 'vpnuser'
    log = logging.getLogger(__name__ + '.ListVpnUser')
    list_columns = ['id', 'name', 'created_at']
    pagination_support = True
    sorting_support = True


class ShowVpnUser(neutronV20.ShowCommand):
    """Show vpnuser information."""

    resource = 'vpnuser'
    log = logging.getLogger(__name__ + '.ShowVpnUser')


class CreateVpnUser(neutronV20.CreateCommand):
    """Create a vpnuser for a given tenant."""

    resource = 'vpnuser'
    log = logging.getLogger(__name__ + '.CreateVpnUser')

    def add_known_arguments(self, parser):
        parser.add_argument(
            'name',
            help=_('Name of this vpn user'))
        parser.add_argument(
            'password',
            help=_('Password of the vpn user'))
        parser.add_argument(
            '--description',
            help=_('Descrition of the vpn user'))

    def args2body(self, parsed_args):
        body = {'vpnuser': {'name': parsed_args.name,
                            'password': parsed_args.password, }, }

        if parsed_args.description:
            body['vpnuser'].update({'description': parsed_args.description})
        if parsed_args.tenant_id:
            body['vpnuser'].update({'tenant_id': parsed_args.tenant_id})

        return body


class DeleteVpnUser(neutronV20.DeleteCommand):
    """Delete a given vpn user."""

    resource = 'vpnuser'
    log = logging.getLogger(__name__ + '.DeleteVpnUser')


class UpdateVpnUser(neutronV20.UpdateCommand):
    """Update vpn user's information."""

    resource = 'vpnuser'
    log = logging.getLogger(__name__ + '.UpdateVpnUser')
