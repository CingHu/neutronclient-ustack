# Copyright 2014 Blue Box Group, Inc.
# All Rights Reserved
#
# Author: Craig Tracey <craigtracey@gmail.com>
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


def _get_loadbalancer_id(client, loadbalancer_id_or_name):
    return neutronV20.find_resourceid_by_name_or_id(client, 'loadbalancer',
                                                    loadbalancer_id_or_name,
                                                    cmd_resource='loadbalancer')
class ListListener(neutronV20.ListCommand):
    """List listeners that belong to a given tenant."""

    resource = 'listener'
    log = logging.getLogger(__name__ + '.ListListener')
    list_columns = ['id','loadbalancer_id', 'protocol',
                    'protocol_port', 'admin_state_up', 'status', 'keep_alive']
    pagination_support = True
    sorting_support = True

class ListLoadBalancerListener(neutronV20.ListCommand):
    """List listeners that belong to a given loadbalancer."""

    resource = 'lbaas_listener'
    log = logging.getLogger(__name__ + '.ListLoadBalancerListener')
    list_columns = ['id','loadbalancer_id', 'protocol',
                    'protocol_port', 'admin_state_up', 'status', 'keep_alive']
    pagination_support = True
    sorting_support = True
   
    def set_extra_attrs(self, parsed_args):
        self.parent_id = _get_loadbalancer_id(self.get_client(), parsed_args.loadbalancer_id)
 
    def add_known_arguments(self, parser):
        parser.add_argument(
            'loadbalancer_id',
            metavar='LOADBALANCER',
            help=_('ID of the load balancer the listeners belong to.'))


class ShowListener(neutronV20.ShowCommand):
    """Show information of a given listener."""

    resource = 'listener'
    log = logging.getLogger(__name__ + '.ShowListener')


class CreateListener(neutronV20.CreateCommand):
    """Create a listener."""

    resource = 'listener'
    log = logging.getLogger(__name__ + '.CreateListener')

    def add_known_arguments(self, parser):
        parser.add_argument(
            'loadbalancer_id',
            metavar='LOADBALANCER',
            help=_('ID of the load balancer the listener belong to.'))
        parser.add_argument(
            'protocol',
            metavar='PROTOCOL',
            choices=['TCP', 'HTTP', 'HTTPS', 'TERMINATED_HTTPS'],
            help=_('Protocol for the listener.'))
        parser.add_argument(
            'protocol_port',
            metavar='PROTOCOL_PORT',
            help=_('Protocol port for the listener.'))
        parser.add_argument(
            '--connection-limit',
            metavar='CONNETION_LIMIT',
            help=_('The connection limit for the listener.'))
        parser.add_argument(
            '--default-pool-id',
            metavar='POOL',
            help=_('The default pool ID to use.'))
        parser.add_argument(
            '--default-tls-container-id',
            metavar='DEFAULT_TLS_CONTAINER_ID',
            help=_('The default tls container ID to use.'))
        parser.add_argument(
            '--sni_container_ids',
            metavar='SNI_TLS_CONTAINER_IDs',
            help=_('The sni tls container IDs to use.'))
        parser.add_argument(
            '--admin-state-down',
            dest='admin_state', action='store_false',
            help=_('Set admin state up to false.'))
        parser.add_argument(
            '--keep-alive',
            dest='keep_alive', action='store_true',
            help=_('Set keep alive flag.'))
        parser.add_argument(
            '--name',
            required=False,
            help=_('Name of the listener.'))
        parser.add_argument(
            '--description',
            help=_('Description of the listener.'))

    def args2body(self, parsed_args):
        body = {
            self.resource: {
                'loadbalancer_id': parsed_args.loadbalancer_id,
                'protocol': parsed_args.protocol,
                'protocol_port': parsed_args.protocol_port,
                'admin_state_up': parsed_args.admin_state,
                'keep_alive': parsed_args.keep_alive,
            },
        }
        neutronV20.update_dict(parsed_args, body[self.resource],
                               ['default_tls_container_id','sni_container_ids',
                               'connection_limit','tenant_id','default_pool_id',
                               'name','description'])
        return body


class UpdateListener(neutronV20.UpdateCommand):
    """Update a given listener."""

    resource = 'listener'
    log = logging.getLogger(__name__ + '.UpdateListener')
    allow_names = False

    def add_known_arguments(self, parser):
        parser.add_argument(
            '--connection-limit',
            metavar='CONNETION_LIMIT',
            help=_('The connection limit for the listener.'))
        parser.add_argument(
            '--default-tls-container-id',
            metavar='DEFAULT_TLS_CONTAINER_ID',
            help=_('The default tls container ID to use.'))
        parser.add_argument(
            '--sni_container_ids',
            metavar='SNI_TLS_CONTAINER_IDs',
            help=_('The sni tls container IDs to use.'))
        parser.add_argument(
            '--default-pool-id',
            metavar='POOL',
            help=_('The default pool ID to use.'))
        parser.add_argument(
            '--admin-state-down',
            dest='admin_state', action='store_false',
            help=_('Set admin state up to false.'))
        parser.add_argument(
            '--name',
            required=False,
            help=_('Name of the listener.'))
        parser.add_argument(
            '--description',
            help=_('Description of the listener.'))


    def args2body(self, parsed_args):
        body = {
            self.resource: {
                'admin_state_up': parsed_args.admin_state,
            },
        }
        neutronV20.update_dict(parsed_args, body[self.resource],
                               ['connection_limit','default_tls_container_id',
                                'sni_container_ids',
                                'default_pool_id','name','description'])
        return body



class DeleteListener(neutronV20.DeleteCommand):
    """Delete a given listener."""

    resource = 'listener'
    log = logging.getLogger(__name__ + '.DeleteListener')
