# Copyright 2013 Mirantis Inc.
# Copyright 2014 Blue Box Group, Inc.
# All Rights Reserved
#
# Author: Ilya Shakhat, Mirantis Inc.
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


def _parse_persistence(parsed_args):
    persistence = None
    if parsed_args.session_persistence:
        parts = parsed_args.session_persistence.split(':')
        if not len(parts) == 2:
            raise Exception('Incorrect --session-persistence format.'
                            ' Format is <TYPE>:<VALUE>')
        if((parts[0] == 'SOURCE_IP' or parts[0] == 'HTTP_COOKIE') and parts[1]!=''):
            raise Exception('Incorrect --session-persistence for SOURCE_IP/HTTP_COOKIE type.'
                            ' Should be SOURCE_IP:\'\' or HTTP_COOKIE:\'\'')
        
        if( (parts[0] == 'SOURCE_IP' or parts[0] == 'HTTP_COOKIE') and parts[1]==''):
            persistence = {'type': parts[0]}
        else:
            persistence = {'type': parts[0], 'cookie_name': parts[1]}
            
    return persistence

def _parse_healthmonitor(parsed_args):
    healthmonitor = None
    if parsed_args.healthmonitor:
        parts = parsed_args.healthmonitor.split('::')
        if not len(parts) == 4 :
            raise Exception('Incorrect --healthmonitor format.'
                            ' Format is <CHECK_INTERNAL>::<TIMEOUT>::<MAX_TRY>::<TYPE_STRING>')
        type_parts = parts[3].split(':')
        if not (type_parts[0] !='HTTP' or type_parts[0] != 'TCP'):
            raise Exception('Incorrect --healthmonitor type should be HTTP or TCP.')
        if(type_parts[0] == 'HTTP' and len(type_parts)!=4 ):
            raise Exception('Incorrect --healthmonitor type format for HTTP.'
                            ' Format is <TYPE>:<HTTP_METHOD>:<URL_PATH>:<EXPECTED_CODE>')
        if(type_parts[0] == 'TCP' and len(type_parts)!=1 ):
            raise Exception('Incorrect --healthmonitor type format for TCP.'
                            ' Format is only <TYPE>')
        if(type_parts[0] == 'HTTP' ):
            healthmonitor = {'type': type_parts[0],'http_method':type_parts[1],
                             'url_path':type_parts[2],'expected_codes':type_parts[3],
                             'delay': parts[0], 'timeout': parts[1], 'max_retries': parts[2]}
        elif (type_parts[0] == 'TCP'):
            healthmonitor = {'type': type_parts[0],'delay': parts[0], 'timeout': parts[1], 'max_retries': parts[2]}
        else:
            raise Exception('Incorrect --TYPE,should be TCP or HTTP.')
        if len(type_parts)!=4 and type_parts[0]!='TCP':
            raise Exception('Incorrect --healthmonitor type only for HTTP can HTTP attributes config.')
            
    return healthmonitor


class ListPool(neutronV20.ListCommand):
    """List pools that belong to a given tenant."""

    resource = 'pool'
    shadow_resource = 'lbaas_pool'
    log = logging.getLogger(__name__ + '.ListPool')
    list_columns = ['id', 'name', 'protocol', 'lb_algorithm','admin_state_up', 'status']
    pagination_support = True
    sorting_support = True


class ShowPool(neutronV20.ShowCommand):
    """Show information of a given pool."""

    resource = 'pool'
    shadow_resource = 'lbaas_pool'
    log = logging.getLogger(__name__ + '.ShowPool')

    def cleanup_output_data(self, data):
        if 'members' not in data['pool']:
            return []
        member_info = []
        for member in data['pool']['members']:
            member_info.append(member['id'])
        data['pool']['members'] = member_info


class CreatePool(neutronV20.CreateCommand):
    """Create a pool."""

    resource = 'pool'
    shadow_resource = 'lbaas_pool'
    log = logging.getLogger(__name__ + '.CreatePool')

    def add_known_arguments(self, parser):
        parser.add_argument(
            'network_id',
            metavar='NETWORK_ID',
            help=_('Network id for pool.'))
        parser.add_argument(
            'protocol',
            metavar='PROTOCOL',
            choices=['TCP', 'HTTP'],
            help=_('Protocol for balancing.'))
        parser.add_argument(
            'lb_algorithm',
            metavar='LB_ALGORITHM',
            choices=['ROUND_ROBIN', 'LEAST_CONNECTIONS', 'SOURCE_IP'],
            help=_('The algorithm used to distribute load between the members '
                   'of the pool.'))
        parser.add_argument(
            '--subnet_id',
            help=_('The subnet of pool to use.'))
        parser.add_argument(
            '--session_persistence', metavar='TYPE:VALUE',
            help=_('The type of session persistence to use.'))
        parser.add_argument(
            '--healthmonitor',
            help=_('Information of the health monitor to use.'))
        parser.add_argument(
            '--admin-state-down',
            dest='admin_state', action='store_false',
            help=_('Set admin state up to false.'))
        parser.add_argument(
            '--name',
            help=_('The name of the pool.'))
        parser.add_argument(
            '--description',
            help=_('Description of the pool.'))

    def args2body(self, parsed_args):
        if parsed_args.session_persistence:
            parsed_args.session_persistence = _parse_persistence(parsed_args)
        if parsed_args.healthmonitor:
            parsed_args.healthmonitor = _parse_healthmonitor(parsed_args)
        body = {
            self.resource: {
                'protocol': parsed_args.protocol,
                'network_id': parsed_args.network_id,
                'lb_algorithm': parsed_args.lb_algorithm,
                'admin_state_up': parsed_args.admin_state,
            },
        }
        neutronV20.update_dict(parsed_args, body[self.resource],
                               ['healthmonitor', 'session_persistence',
                                'name', 'tenant_id','subnet_id','description'])
        return body


class UpdatePool(neutronV20.UpdateCommand):
    """Update a given pool."""

    resource = 'pool'
    shadow_resource = 'lbaas_pool'
    log = logging.getLogger(__name__ + '.UpdatePool')

    def add_known_arguments(self, parser):
        parser.add_argument(
            '--session_persistence', metavar='TYPE:VALUE',
            help=_('The type of session persistence to use.'))
        parser.add_argument(
            '--healthmonitor',
            help=_('Information of the health monitor to use.'))
        parser.add_argument(
            '--admin-state-down',
            dest='admin_state', action='store_false',
            help=_('Set admin state up to false.'))
        parser.add_argument(
            '--name',
            help=_('The name of the pool.'))
        parser.add_argument(
            '--description',
            help=_('Description of the pool.'))

    def args2body(self, parsed_args):
        if parsed_args.session_persistence:
            parsed_args.session_persistence = _parse_persistence(parsed_args)
        if parsed_args.healthmonitor:
            parsed_args.healthmonitor = _parse_healthmonitor(parsed_args)
        body = {
            self.resource: {
                'admin_state_up': parsed_args.admin_state,
            },
        }
        neutronV20.update_dict(parsed_args, body[self.resource],
                               ['healthmonitor', 'session_persistence',
                                'name', 'description'])
        return body


class DeletePool(neutronV20.DeleteCommand):
    """Delete a given pool."""

    resource = 'pool'
    shadow_resource = 'lbaas_pool'
    log = logging.getLogger(__name__ + '.DeletePool')
