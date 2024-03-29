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

import logging

from neutronclient.neutron import v2_0 as neutronv20


_VNF = 'vnf'


class ListVNF(neutronv20.ListCommand):
    """List device that belong to a given tenant."""

    resource = _VNF
    log = logging.getLogger(__name__ + '.ListVNF')


class ShowVNF(neutronv20.ShowCommand):
    """show information of a given VNF."""

    resource = _VNF
    log = logging.getLogger(__name__ + '.ShowVNF')


class CreateVNF(neutronv20.CreateCommand):
    """create a VNF."""

    resource = _VNF
    log = logging.getLogger(__name__ + '.CreateVNF')

    def add_known_arguments(self, parser):
        parser.add_argument(
            '--name',
            help='Set a name for the vnf')
        parser.add_argument(
            '--vnfd-id',
            required=True,
            help='vnfd id to instantiate vnf based on')
        parser.add_argument(
            '--config-file',
            help='specify config yaml file')
        parser.add_argument(
            '--config',
            help='specify config yaml file')

    def args2body(self, parsed_args):
        body = {self.resource: {}}
        if parsed_args.config_file:
            with open(parsed_args.config_file) as f:
                config_yaml = f.read()
            body[self.resource]['config'] = config_yaml
        if parsed_args.config:
            body[self.resource]['config'] = parsed_args.config

        neutronv20.update_dict(parsed_args, body[self.resource],
                              ['tenant_id', 'name', 'vnfd_id'])
        return body


class UpdateVNF(neutronv20.UpdateCommand):
    """Update a given VNF."""

    resource = _VNF
    log = logging.getLogger(__name__ + '.UpdateVNF')

    def add_known_arguments(self, parser):
        parser.add_argument(
            '--config-file',
            help='specify config yaml file')
        parser.add_argument(
            '--config',
            help='specify config yaml file')

    def args2body(self, parsed_args):
        body = {self.resource: {}}
        if parsed_args.config_file:
            with open(parsed_args.config_file) as f:
                config_yaml = f.read()
            body[self.resource]['config'] = config_yaml
        if parsed_args.config:
            body[self.resource]['config'] = parsed_args.config
        neutronv20.update_dict(parsed_args, body[self.resource], ['tenant_id'])
        return body


class DeleteVNF(neutronv20.DeleteCommand):
    """Delete a given VNF."""

    resource = _VNF
    log = logging.getLogger(__name__ + '.DeleteVNF')
