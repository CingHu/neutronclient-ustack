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

import argparse
import logging

from neutronclient.neutron import v2_0 as neutronV20
from neutronclient.openstack.common.gettextutils import _


class ListFloatingIPSet(neutronV20.ListCommand):
    """List floatingipsets that belong to a given tenant."""

    resource = 'floatingipset'
    log = logging.getLogger(__name__ + '.ListFloatingIPSet')
    list_columns = ['id', 'fixed_ip_address', 'floatingipset_address',
                    'port_id']
    pagination_support = True
    sorting_support = True


class ShowFloatingIPSet(neutronV20.ShowCommand):
    """Show information of a given floatingipset."""

    resource = 'floatingipset'
    log = logging.getLogger(__name__ + '.ShowFloatingIPSet')
    allow_names = False


class CreateFloatingIPSet(neutronV20.CreateCommand):
    """Create a floatingipset for a given tenant."""

    resource = 'floatingipset'
    log = logging.getLogger(__name__ + '.CreateFloatingIPSet')

    def add_known_arguments(self, parser):
        parser.add_argument(
            'floatingipset_network_id', metavar='FLOATING_NETWORK',
            help=_('Network name or id to allocate floating IP Set from'))
        parser.add_argument(
            '--port-id',
            help=_('ID of the port to be associated with the floatingipset'))
        parser.add_argument(
            '--port_id',
            help=argparse.SUPPRESS)
        parser.add_argument(
            '--fixed-ip-address',
            help=_('IP address on the port (only required if port has multiple'
                   'IPs)'))
        parser.add_argument(
            '--fixed_ip_address',
            help=argparse.SUPPRESS)
        parser.add_argument(
            '--service-provider', 
            metavar='SERVICE_PROVIDER',
            action='append',
            help=_('The name of service provider for public network'))


    def args2body(self, parsed_args):
        _network_id = neutronV20.find_resourceid_by_name_or_id(
            self.get_client(), 'network', parsed_args.floatingipset_network_id)
        body = {self.resource: {'floatingipset_network_id': _network_id,
                'uos:service_provider':parsed_args.service_provider}}
        if parsed_args.port_id:
            body[self.resource].update({'port_id': parsed_args.port_id})
        if parsed_args.tenant_id:
            body[self.resource].update({'tenant_id': parsed_args.tenant_id})
        if parsed_args.fixed_ip_address:
            body[self.resource].update({'fixed_ip_address':
                                        parsed_args.fixed_ip_address})
        return body


class DeleteFloatingIPSet(neutronV20.DeleteCommand):
    """Delete a given floating ip set."""

    log = logging.getLogger(__name__ + '.DeleteFloatingIPSet')
    resource = 'floatingipset'
    allow_names = False


class AssociateFloatingIPSet(neutronV20.NeutronCommand):
    """Create a mapping between a floating ip set and a fixed ip."""

    api = 'network'
    log = logging.getLogger(__name__ + '.AssociateFloatingIPSet')
    resource = 'floatingipset'

    def get_parser(self, prog_name):
        parser = super(AssociateFloatingIPSet, self).get_parser(prog_name)
        parser.add_argument(
            'floatingipset_id', metavar='FLOATINGIPSETID',
            help=_('ID of the floating IP Set to associate'))
        parser.add_argument(
            'port_id', metavar='PORT',
            help=_('ID or name of the port to be associated with the '
                   'floatingipset'))
        parser.add_argument(
            '--fixed-ip-address',
            help=_('IP address on the port (only required if port has multiple'
                   'IPs)'))
        parser.add_argument(
            '--fixed_ip_address',
            help=argparse.SUPPRESS)
        return parser

    def run(self, parsed_args):
        self.log.debug('run(%s)' % parsed_args)
        neutron_client = self.get_client()
        neutron_client.format = parsed_args.request_format
        update_dict = {}
        if parsed_args.port_id:
            update_dict['port_id'] = parsed_args.port_id
        if parsed_args.fixed_ip_address:
            update_dict['fixed_ip_address'] = parsed_args.fixed_ip_address
        neutron_client.update_floatingipset(parsed_args.floatingipset_id,
                                         {'floatingipset': update_dict})
        print >>self.app.stdout, (
            _('Associated floatingipset %s') % parsed_args.floatingipset_id)


class DisassociateFloatingIPSet(neutronV20.NeutronCommand):
    """Remove a mapping from a floating ip set to a fixed ip.
    """

    api = 'network'
    log = logging.getLogger(__name__ + '.DisassociateFloatingIPSet')
    resource = 'floatingipset'

    def get_parser(self, prog_name):
        parser = super(DisassociateFloatingIPSet, self).get_parser(prog_name)
        parser.add_argument(
            'floatingipset_id', metavar='FLOATINGIPSETID',
            help=_('ID of the floating IP SET to associate'))
        return parser

    def run(self, parsed_args):
        self.log.debug('run(%s)' % parsed_args)
        neutron_client = self.get_client()
        neutron_client.format = parsed_args.request_format
        neutron_client.update_floatingipset(parsed_args.floatingipset_id,
                                         {'floatingipset': {'port_id': None}})
        print >>self.app.stdout, (
            _('Disassociated floatingipset %s') % parsed_args.floatingipset_id)
