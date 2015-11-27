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


class ListHealthMonitor(neutronV20.ListCommand):
    """List healthmonitors that belong to a given tenant."""

    resource = 'healthmonitor'
    shadow_resource = 'lbaas_healthmonitor'
    log = logging.getLogger(__name__ + '.ListHealthMonitor')
    list_columns = ['id', 'type', 'admin_state_up','status']
    pagination_support = True
    sorting_support = True


class ShowHealthMonitor(neutronV20.ShowCommand):
    """Show information of a given healthmonitor."""

    resource = 'healthmonitor'
    shadow_resource = 'lbaas_healthmonitor'
    log = logging.getLogger(__name__ + '.ShowHealthMonitor')


class CreateHealthMonitor(neutronV20.CreateCommand):
    """Create a healthmonitor."""

    resource = 'healthmonitor'
    shadow_resource = 'lbaas_healthmonitor'
    log = logging.getLogger(__name__ + '.CreateHealthMonitor')

    def add_known_arguments(self, parser):
        parser.add_argument(
            'type', metavar='TYPE',
            choices=['PING','TCP', 'HTTP', 'HTTPS'],
            help=_('One of the predefined health monitor types.'))
        parser.add_argument(
            'delay', metavar='CHECK_INTERNAL',
            help=_('The time in seconds between sending probes to members.'))
        parser.add_argument(
            'timeout_second',metavar='TIMEOUT_SECOND',
            help=_('Maximum number of seconds for a monitor to wait for a '
                   'connection to be established before it times out. The '
                   'value must be less than the delay value.'))
        parser.add_argument(
            'max_retries',metavar='MAX_RETRIES',
            help=_('Number of permissible connection failures before changing '
                   'the member status to INACTIVE. [1..10].'))
        parser.add_argument(
            '--admin-state-down',
            dest='admin_state', action='store_false',
            help=_('Set admin state up to false.'))
        parser.add_argument(
            '--http-method',
            help=_('The HTTP method used for requests by the monitor of type '
                   'http.'))
        parser.add_argument(
            '--url-path',
            help=_('The HTTP path used in the HTTP request used by the monitor'
                   ' to test a member health. This must be a string '
                   'beginning with a / (forward slash).'))
        parser.add_argument(
            '--expected-codes',
            help=_('The list of HTTP status codes expected in '
                   'response from the member to declare it healthy. This '
                   'attribute can contain one value, '
                   'or a list of values separated by comma, '
                   'or a range of values (e.g. "200-299"). If this attribute '
                   'is not specified, it defaults to "200".'))

    def args2body(self, parsed_args):
        body = {
            self.resource: {
                'admin_state_up': parsed_args.admin_state,
                'delay': parsed_args.delay,
                'max_retries': parsed_args.max_retries,
                'timeout': parsed_args.timeout_second,
                'type': parsed_args.type,
            },
        }
        neutronV20.update_dict(parsed_args, body[self.resource],
                               ['expected_codes', 'http_method', 'url_path',
                                'tenant_id'])
        return body


class UpdateHealthMonitor(neutronV20.UpdateCommand):
    """Update a given healthmonitor."""

    resource = 'healthmonitor'
    shadow_resource = 'lbaas_healthmonitor'
    log = logging.getLogger(__name__ + '.UpdateHealthMonitor')
    allow_names = False

    def add_known_arguments(self, parser):
        parser.add_argument(
            '--delay',
            help=_('The time in seconds between sending probes to members.'))
        parser.add_argument(
            '--timeout_second',
            help=_('Maximum number of seconds for a monitor to wait for a '
                   'connection to be established before it times out. The '
                   'value must be less than the delay value.'))
        parser.add_argument(
            '--max_retries',
            help=_('Number of permissible connection failures before changing '
                   'the member status to INACTIVE. [1..10].'))
        parser.add_argument(
            '--admin-state-down',
            dest='admin_state', action='store_false',
            help=_('Set admin state up to false.'))
        parser.add_argument(
            '--http-method',
            help=_('The HTTP method used for requests by the monitor of type '
                   'http.'))
        parser.add_argument(
            '--url-path',
            help=_('The HTTP path used in the HTTP request used by the monitor'
                   ' to test a member health. This must be a string '
                   'beginning with a / (forward slash).'))
        parser.add_argument(
            '--expected-codes',
            help=_('The list of HTTP status codes expected in '
                   'response from the member to declare it healthy. This '
                   'attribute can contain one value, '
                   'or a list of values separated by comma, '
                   'or a range of values (e.g. "200-299"). If this attribute '
                   'is not specified, it defaults to "200".'))

    def args2body(self, parsed_args):
        body = {
            self.resource: {
                'admin_state_up': parsed_args.admin_state,
            },
        }
        neutronV20.update_dict(parsed_args, body[self.resource],
                               ['timeout','type','delay','max_retries','expected_codes', 'http_method', 'url_path',
                                'tenant_id'])
        return body


class DeleteHealthMonitor(neutronV20.DeleteCommand):
    """Delete a given healthmonitor."""

    resource = 'healthmonitor'
    shadow_resource = 'lbaas_healthmonitor'
    log = logging.getLogger(__name__ + '.DeleteHealthMonitor')
