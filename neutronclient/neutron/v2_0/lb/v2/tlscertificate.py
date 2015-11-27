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


class ShowTLSCertificate(neutronV20.ShowCommand):
    """Show information of a given tlscertificate."""

    resource = 'tlscertificate'
    shadow_resource = 'tlscertificate'
    log = logging.getLogger(__name__ + '.ShowTLSCertificate')


class ListTLSCertificate(neutronV20.ListCommand):
    """List tlscertificates that belong to a given tenant."""

    resource = 'tlscertificate'
    shadow_resource = 'tlscertificate'
    log = logging.getLogger(__name__ + '.ListTLSCertificate')
    list_columns = [
        'id', 'listener_id', 'name', 'certificate_content',
        'private_key','status','description'
    ]
    pagination_support = True
    sorting_support = True


class CreateTLSCertificate(neutronV20.CreateCommand):
    """Create a tlscertificate."""

    resource = 'tlscertificate'
    shadow_resource = 'tlscertificate'
    log = logging.getLogger(__name__ + '.CreateTLSCertificate')

    def add_known_arguments(self, parser):
        parser.add_argument(
            'certificate_content', metavar='CERTIFICATE_CONTENT',
            help=_('Certificate content of the tls certificate.'))
        parser.add_argument(
            'private_key',  metavar='PRIVATE_KEY',
            help=_('The private key.'))
        parser.add_argument(
            '--name',
            required=False,
            help=_('Set name'))
        parser.add_argument(
            '--description',
            required=False,
            help=_('Set description'))

    def args2body(self, parsed_args):
        body = {
            self.resource: {
                      'certificate_content':parsed_args.certificate_content,
                      'private_key':parsed_args.private_key,
                           }
        }
        neutronV20.update_dict(parsed_args, body[self.resource],
                               ['name','description'])
        return body

class UpdateTLSCertificate(neutronV20.UpdateCommand):
    """Update a given tlscertificate."""
    resource = 'tlscertificate'
    shadow_resource = 'tlscertificate'
    log = logging.getLogger(__name__ + '.UpdateTLSCertificate')

    def add_known_arguments(self, parser):
        parser.add_argument(
            '--certificate_content', 
            required=False,
            help=_('Certificate content of the tls certificate.'))
        parser.add_argument(
            '--private_key', 
            required=False,
            help=_('The private key.'))
        parser.add_argument(
            '--name',
            required=False,
            help=_('Set name'))
        parser.add_argument(
            '--description',
            required=False,
            help=_('Set description'))



    def args2body(self, parsed_args):
        body = {
            self.resource: {}
        }
        neutronV20.update_dict(parsed_args, body[self.resource],
                               ['name','description','certificate_content','private_key'])
        return body


class DeleteTLSCertificate(neutronV20.DeleteCommand):
    """Delete a given tlscertificate."""

    resource = 'tlscertificate'
    shadow_resource = 'tlscertificate'
    log = logging.getLogger(__name__ + '.DeleteTLSCertificate')
