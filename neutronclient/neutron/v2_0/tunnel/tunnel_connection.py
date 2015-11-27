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

from neutronclient.common import exceptions
from neutronclient.common import utils
from neutronclient.neutron import v2_0 as neutronv20
from neutronclient.openstack.common.gettextutils import _


class ListTunnelConnection(neutronv20.ListCommand):
    """List TunnelConnections that belong to a given tenant."""

    resource = 'tunnel_connection'
    log = logging.getLogger(__name__ + '.ListTunnelConnection')
    list_columns = [
        'id', 'remote_ip', 'key', 'key_type',
        'checksum', 'status', 'tunnel_id']
    pagination_support = True
    sorting_support = True


class ShowTunnelConnection(neutronv20.ShowCommand):
    """Show information of a given TunnelConnection."""

    resource = 'tunnel_connection'
    log = logging.getLogger(__name__ + '.ShowTunnelConnection')


class CreateTunnelConnection(neutronv20.CreateCommand):
    """Create an TunnelConnection."""
    resource = 'tunnel_connection'
    log = logging.getLogger(__name__ + '.CreateTunnelConnection')

    def add_known_arguments(self, parser):
        parser.add_argument(
            '--tunnel_id',
            required=True,
            help=_('Tunnel ID'))
        parser.add_argument(
            '--key',
            help=_('key'))
        parser.add_argument(
            '--key_type',
            required=True,
            help=_('key_type'))
        parser.add_argument(
            '--checksum',
            required=True,
            help=_('checksum'))
        parser.add_argument(
            '--remote_ip',
            required=True,
            help=_('remote_ip'))

    def args2body(self, parsed_args):
        _tunnel_id = neutronv20.find_resourceid_by_name_or_id(
            self.get_client(), 'tunnel',
            parsed_args.tunnel_id)
        body = {'tunnel_connection': {
            'tunnel_id': _tunnel_id,
            'key': parsed_args.key,
            'key_type': parsed_args.key_type,
            'checksum': parsed_args.checksum,
            'remote_ip': parsed_args.remote_ip,
        }, }
        return body


class UpdateTunnelConnection(neutronv20.UpdateCommand):
    """Update a given TunnelConnection."""

    resource = 'tunnel_connection'
    log = logging.getLogger(__name__ + '.UpdateTunnelConnection')

    def add_known_arguments(self, parser):
        parser.add_argument(
            '--tunnel_id',
            help=_('Tunnel ID'))
        parser.add_argument(
            '--key',
            help=_('key'))
        parser.add_argument(
            '--key_type',
            help=_('key_type'))
        parser.add_argument(
            '--checksum',
            help=_('checksum'))
        parser.add_argument(
            '--remote_ip',
            help=_('remote_ip'))

    def args2body(self, parsed_args):
        body = {'tunnel_connection': {
            'tunnel_id': parsed_args.tunnel_id,
            'key': parsed_args.key,
            'key_type': parsed_args.key_type,
            'checksum': parsed_args.checksum,
            'remote_ip': parsed_args.remote_ip,
        }, }

        return body


class DeleteTunnelConnection(neutronv20.DeleteCommand):
    """Delete a given TunnelConnection."""

    resource = 'tunnel_connection'
    log = logging.getLogger(__name__ + '.DeleteTunnelConnection')
