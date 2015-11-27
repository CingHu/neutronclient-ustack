#
# Copyright 2013 Intel
# Copyright 2013 Isaku Yamahata <isaku.yamahata at intel com>
#                               <isaku.yamahata at gmail com>
# All Rights Reserved.
#
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
# @author: Isaku Yamahata, Intel

import argparse
import logging


from neutronclient.neutron import v2_0 as neutronv20


_SERVICE_INSTANCE = "service_instance"

from neutronclient.openstack.common.gettextutils import _

class ListServiceInstance(neutronv20.ListCommand):
    """List service instance that belong to a given tenant."""

    resource = _SERVICE_INSTANCE 
    log = logging.getLogger(__name__ + '.ListServiceInstance')
    list_columns = ['id', 'name', 'devices', 'service_type_id','status']
    pagination_support = True
    sorting_support = True


class ShowServiceInstance(neutronv20.ShowCommand):
    """show information of a given Service Instance."""

    resource = _SERVICE_INSTANCE
    log = logging.getLogger(__name__ + '.ShowServiceInstance')



class CreateServiceInstance(neutronv20.CreateCommand):
    """create a Service Instance."""
    resource = _SERVICE_INSTANCE
    log = logging.getLogger(__name__ + '.CreateServiceInstance')

    def add_known_arguments(self, parser):
        parser.add_argument(
            '--name',
            required=False,
            help='Set a name for the devicetemplate')
        parser.add_argument(
            '--description',
            help='Set a description for the devicetemplate')
        parser.add_argument(
            '--service-type-id',
            required=True,
            help='Set a servicetype for the service instance')
        parser.add_argument(
            '--service-table-id',
            help='Set a row in service specific table if any')
        parser.add_argument(
            '--managed-by-user',
            action='store_true',
            required=False,
            help='user be able to change its configurations',
            default=argparse.SUPPRESS)
        parser.add_argument(
            '--mgmt-driver',
            help='Set a mgmt driver to communicate with logical service instance')
        parser.add_argument(
            '--attribute',
            nargs=2,
            action='append',
            help='Set  attribute for the service instance')
        parser.add_argument(
            '--mgmt-url',
            help='Set a manegement url for the service instance')
        parser.add_argument(
            '--devices',
            action='append',
            required=True,
            help='Set devices for service instances')

    def args2body(self, parsed_args):
        body = {
            self.resource: {
                'devices': parsed_args.devices,
#                'service_type_id': parsed_args.service_type_id,
            }
        }
        if parsed_args.attribute:
            body[self.resource]['attributes'] = dict(parsed_args.attribute)
        if parsed_args.service_table_id:
            body[self.resource]['service_table_id'] = parsed_args.service_table_id
        #if parsed_args.managed_by_user:
        #    body[self.resource]['managed_by_user'] = parsed_args.managed_by_user
        neutronv20.update_dict(parsed_args, body[self.resource],
                     ['tenant_id', 'name','managed_by_user','mgmt_driver',
                      'mgmt_url','service_type_id'])
        return body


class UpdateServiceInstance(neutronv20.UpdateCommand):
    """Update a given Service Instance."""

    resource = _SERVICE_INSTANCE
    log = logging.getLogger(__name__ + '.UpdateServiceInstance')
    allow_names = False


class DeleteServiceInstance(neutronv20.DeleteCommand):
    """Delete a given Service Instance."""
    resource = _SERVICE_INSTANCE
    log = logging.getLogger(__name__ + '.DeleteServiceInstance')
