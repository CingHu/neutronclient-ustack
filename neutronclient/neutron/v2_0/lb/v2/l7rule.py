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


def _get_l7policy_id(client, l7policy_id_or_name):
    return neutronV20.find_resourceid_by_name_or_id(client, 'l7policy',
                                                    l7policy_id_or_name,
                                                    cmd_resource='l7policy')


class LbaasL7RuleMixin(object):

    def set_extra_attrs(self, parsed_args):
        self.parent_id = _get_l7policy_id(self.get_client(), parsed_args.l7policy_id)

    def add_known_arguments(self, parser):
        parser.add_argument(
            'l7policy_id', metavar='L7POLICY',
            help=_('ID of the l7policy that this l7rule belongs to.'))


class ShowL7Rule(LbaasL7RuleMixin,neutronV20.ShowCommand):
    """Show information of a given l7rule."""

    resource = 'rule'
    shadow_resource = 'rule'
    log = logging.getLogger(__name__ + '.ShowL7Rule')


class ListL7Rule(LbaasL7RuleMixin,neutronV20.ListCommand):
    """List l7rules that belong to a given tenant."""

    resource = 'rule'
    shadow_resource = 'rule'
    log = logging.getLogger(__name__ + '.ListL7Rule')
    list_columns = [
        'id', 'l7policy_id', 'type', 'compare_type',
        'key', 'admin_state_up', 'status'
    ]
    pagination_support = True
    sorting_support = True


class CreateL7Rule(neutronV20.CreateCommand):
    """Create a l7rule."""

    resource = 'rule'
    shadow_resource = 'rule'
    log = logging.getLogger(__name__ + '.CreateL7Rule')

    def add_known_arguments(self, parser):
        parser.add_argument(
            'l7policy_id', metavar='L7POLICY',
            help=_('ID of the l7policy that this l7rule belongs to.'))
        parser.add_argument(
            'type',  metavar='TYPE',
            help=_('The type of the l7rule.'))
        parser.add_argument(
            'compare_type', metavar='COMPARE_TYPE',
            help=_('The compare type of the l7rule.'))
        parser.add_argument(
            'key',  metavar='COMPARE_CONTENT',
            help=_('The content to compare of the l7rule.'))

        #parser.add_argument(
        #    '--value',
        #    required=False,
        #    help=_('Value of the l7rule.'))
        parser.add_argument(
            '--admin-state-down',
            dest='admin_state', action='store_false',
            help=_('Set admin state up to false'))

    def args2body(self, parsed_args):
        self.parent_id = _get_l7policy_id(self.get_client(), parsed_args.l7policy_id)
        body = {
            self.resource: {
                'admin_state_up': parsed_args.admin_state,
                'type': parsed_args.type,
                'compare_type': parsed_args.compare_type,
            },
        }
        neutronV20.update_dict(parsed_args, body[self.resource],
                               ['key','value','tenant_id'])
        return body

class UpdateL7Rule(LbaasL7RuleMixin,neutronV20.UpdateCommand):
    """Update a given l7rule."""
    resource = 'rule'
    shadow_resource = 'rule'
    log = logging.getLogger(__name__ + '.UpdateL7Rule')

    def add_known_arguments(self, parser):
        parser.add_argument(
            'l7policy_id', metavar='L7POLICY',
            help=_('ID of the l7policy that this l7rule belongs to.'))
        parser.add_argument(
            '--key',
            required=False,
            help=_('Key of the l7rule.'))
        #parser.add_argument(
        #    '--value',
        #    required=False,
        #    help=_('Value of the l7rule.'))

    def args2body(self, parsed_args):
        body = {
            self.resource: {}
        }
        neutronV20.update_dict(parsed_args, body[self.resource],
                               ['key','value'])
        return body


class DeleteL7Rule(LbaasL7RuleMixin,neutronV20.DeleteCommand):
    """Delete a given l7rule."""

    resource = 'rule'
    shadow_resource = 'rule'
    log = logging.getLogger(__name__ + '.DeleteL7Rule')
