# Copyright 2013 OpenStack Foundation.
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

from neutronclient.common import exceptions
from neutronclient.neutron import v2_0 as neutronV20
from neutronclient.openstack.common.gettextutils import _


def _format_timestamp(component):
    try:
        return component['heartbeat_timestamp'].split(".", 2)[0]
    except Exception:
        return ''


class ListAgent(neutronV20.ListCommand):
    """List agents."""

    resource = 'agent'
    log = logging.getLogger(__name__ + '.ListAgent')
    list_columns = ['id', 'agent_type', 'host', 'alive', 'admin_state_up']
    _formatters = {'heartbeat_timestamp': _format_timestamp}

    def extend_list(self, data, parsed_args):
        for agent in data:
            if 'alive' in agent:
                agent['alive'] = ":-)" if agent['alive'] else 'xxx'

class CreateAgent(neutronV20.CreateCommand):
    """Create an agent."""

    resource = 'agent'
    log = logging.getLogger(__name__ + '.CreateAgent')
    agent_binaries = {'L3 agent': 'neutron-l3-agent',
                      'DHCP agent': 'neutron-dhcp-agent'}
    agent_topics = {'L3 agent': 'l3_agent',
                    'DHCP agent': 'dhcp_agent'}

    def add_known_arguments(self, parser):
        parser.add_argument(
            'agent_type',
            help=_('agent type, such as L3 agent, DHCP agent'))
        parser.add_argument(
            'host',
            help=_('host the agent is running on'))
        parser.add_argument(
            '--binary',
            help=_('agent binary, such as neutron-l3-agent, neutron-dhcp-agent'))
        parser.add_argument(
            '--topic',
            help=_('the agent topic, such as l3_agent, dhcp_agent'))
        parser.add_argument(
            '--non-reserved',
            dest='reserved', action='store_false',
            help=_('set the reserved flag to false'))

    def args2body(self, parsed_args):
        body = {self.resource: {'agent_type': parsed_args.agent_type}}
        body[self.resource].update({'host': parsed_args.host})
        body[self.resource].update({'reserved': parsed_args.reserved})
        binary = parsed_args.binary
        if not binary:
            binary = self.agent_binaries.get(parsed_args.agent_type)
            if not binary:
                raise exceptions.Invalid("cannot find binary")
        body[self.resource].update({'binary': binary})
        topic = parsed_args.topic
        if not topic:
            topic = self.agent_topics.get(parsed_args.agent_type)
            if not topic:
                raise exceptions.Invalid("cannot find topic")
        body[self.resource].update({'topic': topic})
        return body


class ShowAgent(neutronV20.ShowCommand):
    """Show information of a given agent."""

    resource = 'agent'
    log = logging.getLogger(__name__ + '.ShowAgent')
    allow_names = False
    json_indent = 5


class DeleteAgent(neutronV20.DeleteCommand):
    """Delete a given agent."""

    log = logging.getLogger(__name__ + '.DeleteAgent')
    resource = 'agent'
    allow_names = False


class UpdateAgent(neutronV20.UpdateCommand):
    """Update a given agent."""

    log = logging.getLogger(__name__ + '.UpdateAgent')
    resource = 'agent'
    allow_names = False
