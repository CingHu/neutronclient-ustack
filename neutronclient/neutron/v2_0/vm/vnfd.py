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


_VNFD = "vnfd"


class ListVNFD(neutronv20.ListCommand):
    """List VNFD that belong to a given tenant."""

    resource = _VNFD
    log = logging.getLogger(__name__ + '.ListVNFD')


class ShowVNFD(neutronv20.ShowCommand):
    """show information of a given VNFD."""

    resource = _VNFD
    log = logging.getLogger(__name__ + '.ShowVNFD')


class CreateVNFD(neutronv20.CreateCommand):
    """create a VNFD."""

    stVNFDresource = _VNFD
    log = logging.getLogger(__name__ + '.CreateVNFD')

    def add_known_arguments(self, parser):
        parser.add_argument(
            '--name',
            help='Set a name for the vnfd')
        parser.add_argument(
            '--description',
            help='Set a description for the vnfd')
        parser.add_argument(
            '--vnfd-file',
            help='specify vnfd file')
        parser.add_argument(
            '--vnfd',
            help='specify vnfd')

    def args2body(self, parsed_args):
        body = {self.resource: {}}
        if parsed_args.vnfd_file:
            with open(parsed_args.vnfd_file) as f:
                vnfd = f.read()
        if parsed_args.vnfd:
            vnfd = parsed_args.vnfd
        body[self.resource]['vnfd'] = vnfd
        neutronv20.update_dict(parsed_args, body[self.resource],
                              ['tenant_id', 'name', 'description'])
        return body


class DeleteVNFD(neutronv20.DeleteCommand):
    """Delete a given VNFD."""
    resource = _VNFD
    log = logging.getLogger(__name__ + '.DeleteVNFD')
