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


class ListLoadBalancer(neutronV20.ListCommand):
    """List loadbalancers that belong to a given tenant."""

    resource = 'loadbalancer'
    log = logging.getLogger(__name__ + '.ListLoadBalancer')
    list_columns = ['id', 'name', 'vip_address',
                    'admin_state_up', 'status']
    pagination_support = True
    sorting_support = True


class ShowLoadBalancer(neutronV20.ShowCommand):
    """Show information of a given loadbalancer."""

    resource = 'loadbalancer'
    log = logging.getLogger(__name__ + '.ShowLoadBalancer')


class CreateLoadBalancer(neutronV20.CreateCommand):
    """Create a loadbalancer."""

    resource = 'loadbalancer'
    log = logging.getLogger(__name__ + '.CreateLoadBalancer')

    def add_known_arguments(self, parser):
        parser.add_argument(
            'vip_network_id', metavar='VIP_NETWORK_ID',
            help=_('ID of the load balancer network.'))
        parser.add_argument(
            'securitygroup_id', metavar='SECURITYGROUP_ID',
            help=_('Security group of the load balancer.'))
        parser.add_argument(
            '--vip_subnet_id',
            required=False,
            help=_('ID of the load balancer subnet.'))
        parser.add_argument(
            '--vip_address',
            required=False,
            help=_('VIP address of the load balancer.'))
        parser.add_argument(
            '--name',
            required=False,
            help=_('Name of the load balancer.'))
        parser.add_argument(
            '--description',
            help=_('Description of the load balancer.'))

    def args2body(self, parsed_args):
        body = {
            self.resource: {
                'vip_network_id': parsed_args.vip_network_id,
                'securitygroup_id': parsed_args.securitygroup_id,
            },
        }
        neutronV20.update_dict(parsed_args, body[self.resource],
                               ['vip_subnet_id','name','tenant_id','vip_address', 'description'])
        return body


class UpdateLoadBalancer(neutronV20.UpdateCommand):
    """Update a given loadbalancer."""

    resource = 'loadbalancer'
    log = logging.getLogger(__name__ + '.UpdateLoadBalancer')
    allow_names = False

    def add_known_arguments(self, parser):
       parser.add_argument(
            '--name',
            required=False,
            help=_('Name of the load balancer.'))
       parser.add_argument(
            '--securitygroup_id',
            required=False,
            help=_('Security group of the load balancer.'))
       parser.add_argument(
            '--description',
            help=_('Description of the load balancer.'))

    def args2body(self, parsed_args):
        body = {
            self.resource: {
            },
        }
        neutronV20.update_dict(parsed_args, body[self.resource],
                               ['name','securitygroup_id', 'description'])
        return body

class DeleteLoadBalancer(neutronV20.DeleteCommand):
    """Delete a given loadbalancer."""

    resource = 'loadbalancer'
    log = logging.getLogger(__name__ + '.DeleteLoadBalancer')


class RetrieveLoadBalancerStats(neutronV20.ShowCommand):
    """Retrieve stats for a given loadbalancer."""

    resource = 'loadbalancer'
    log = logging.getLogger(__name__ + '.RetrieveLoadBalancerStats')

    def get_data(self, parsed_args):
        self.log.debug('run(%s)' % parsed_args)
        neutron_client = self.get_client()
        neutron_client.format = parsed_args.request_format
        loadbalancer_id = neutronV20.find_resourceid_by_name_or_id(
            self.get_client(), 'loadbalancer', parsed_args.id)
        params = {}
        data = neutron_client.retrieve_loadbalancer_stats(loadbalancer_id, **params)
        self.format_output_data(data)
        stats = data['stats']
        if 'stats' in data:
            return zip(*sorted(stats.iteritems()))
        else:
            return None


