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


def _get_listener_id(client, listener_id_or_name):
    return neutronV20.find_resourceid_by_name_or_id(client, 'listener',
                                                    listener_id_or_name,
                                                    cmd_resource='listener')


class LbaasL7PolicyMixin(object):

    def set_extra_attrs(self, parsed_args):
        self.parent_id = _get_listener_id(self.get_client(), parsed_args.listener_id)

    def add_known_arguments(self, parser):
        parser.add_argument(
            'listener_id', metavar='Listener',
            help=_('ID of the listener that this l7policy belongs to.'))


class ShowL7Policy(neutronV20.ShowCommand):
    """Show information of a given l7policy."""

    resource = 'l7policy'
    shadow_resource = 'l7policy'
    log = logging.getLogger(__name__ + '.ShowL7Policy')

class ListListenerL7Policy(neutronV20.ListCommand):
    """List listeners that belong to a given loadbalancer."""

    resource = 'lbaas_l7policie'
    log = logging.getLogger(__name__ + '.ListListenerL7Policy')
    list_columns = [
        'id','name', 'listener_id', 'action',
        'position', 'admin_state_up', 'status','description'
    ]
   
    def set_extra_attrs(self, parsed_args):
        self.parent_id = _get_listener_id(self.get_client(), parsed_args.listener_id)
 
    def add_known_arguments(self, parser):
        parser.add_argument(
            'listener_id',
            metavar='LISTENER',
            help=_('ID of the listener the l7policies belong to.'))


class ListL7Policy(neutronV20.ListCommand):
    """List l7policies that belong to a given tenant."""

    resource = 'l7policie'
    shadow_resource = 'l7policie'
    log = logging.getLogger(__name__ + '.ListL7Policy')
    list_columns = [
        'id','name', 'listener_id', 'action',
        'position', 'admin_state_up', 'status','description'
    ]
    pagination_support = True
    sorting_support = True


class CreateL7Policy(neutronV20.CreateCommand):
    """Create a l7policy."""

    resource = 'l7policy'
    shadow_resource = 'l7policy'
    log = logging.getLogger(__name__ + '.CreateL7Policy')

    def add_known_arguments(self, parser):
        parser.add_argument(
            'listener_id', metavar='LISTENER',
            help=_('ID of the listener that this l7policy belongs to.'))
        parser.add_argument(
            'action', metavar='ACTION',
            help=_('The action of the l7policy.'))
        parser.add_argument(
            '--redirect-pool-id',
            required=False,
            help=_('ID of the pool that this l7policy apply to.'))
        parser.add_argument(
            '--redirect-url',
            required=False,
            help=_('URL that this l7policy redirect to.'))
        parser.add_argument(
            '--redirect-url-code',
            required=False,
            help=_('URL redirect code that this l7policy uses.'))
        parser.add_argument(
            '--redirect-url-drop-query',
            required=False,
            help=_('URL redirect whether drop query.'))
        parser.add_argument(
            '--position',
            required=False,
            help=_('The l7policy apply sequence number.'))
        parser.add_argument(
            '--admin-state-down',
            dest='admin_state', action='store_false',
            help=_('Set admin state up to false'))
        parser.add_argument(
            '--name',
            required=False,
            help=_('Name of the listener.'))
        parser.add_argument(
            '--description',
            help=_('Description of the listener.'))

    def args2body(self, parsed_args):
        #self.parent_id = _get_listener_id(self.get_client(), parsed_args.listener_id)
        body = {
            self.resource: {
                'listener_id': parsed_args.listener_id,
                'action': parsed_args.action,
                'admin_state_up': parsed_args.admin_state,
            },
        }
        neutronV20.update_dict(parsed_args, body[self.resource],
                               ['redirect_pool_id','redirect_url',
                                'redirect_url_code',
                                'redirect_url_drop_query',
                                'position','name','tenant_id','description'])
        return body

class UpdateL7Policy(neutronV20.UpdateCommand):
    """Update a given l7policy."""
    resource = 'l7policy'
    shadow_resource = 'l7policy'
    log = logging.getLogger(__name__ + '.UpdateL7Policy')

    def add_known_arguments(self, parser):
        parser.add_argument(
            '--action',
            required=False,
            help=_('The action of the l7policy.'))
        parser.add_argument(
            '--redirect-pool-id',
            required=False,
            help=_('ID of the pool that this l7policy apply to.'))
        parser.add_argument(
            '--redirect-url',
            required=False,
            help=_('URL that this l7policy redirect to.'))
        parser.add_argument(
            '--redirect-url-code',
            required=False,
            help=_('URL redirect code that this l7policy uses.'))
        parser.add_argument(
            '--redirect-url-drop-query',
            required=False,
            help=_('URL redirect whether drop query.'))
        parser.add_argument(
            '--position',
            required=False,
            help=_('The l7policy apply sequence number.'))
        parser.add_argument(
            '--admin-state-down',
            dest='admin_state', action='store_false',
            help=_('Set admin state up to false'))
        parser.add_argument(
            '--name',
            required=False,
            help=_('Name of the listener.'))
        parser.add_argument(
            '--description',
            help=_('Description of the listener.'))

    def args2body(self, parsed_args):
        body = {
            self.resource: {}
        }
        neutronV20.update_dict(parsed_args, body[self.resource],
                               ['action', 'name','description','redirect_url',
                                'redirect_pool_id', 'redirect_url_code',
                                'redirect_url_drop_query' ,
                                'admin_state_up', 'position'])
        return body


class DeleteL7Policy(neutronV20.DeleteCommand):
    """Delete a given l7policy."""

    resource = 'l7policy'
    shadow_resource = 'l7policy'
    log = logging.getLogger(__name__ + '.DeleteL7Policy')
