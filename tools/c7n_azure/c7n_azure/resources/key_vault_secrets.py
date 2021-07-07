# Copyright The Cloud Custodian Authors.
# SPDX-License-Identifier: Apache-2.0

import logging

from azure.keyvault.keys import KeyProperties

from c7n.filters import Filter
from c7n.utils import type_schema

from c7n_azure import constants
from c7n_azure.provider import resources
from c7n_azure.query import ChildResourceManager, ChildTypeInfo
from c7n_azure.utils import ThreadHelper, ResourceIdParser


log = logging.getLogger('custodian.azure.keyvault.keys')


@resources.register('keyvault-secret', aliases=['keyvault-secrets'])
class KeyVaultSecrets(ChildResourceManager):
    """Key Vault Secret Resource

    :example:


    """

    class resource_type(ChildTypeInfo):
        doc_groups = ['Security']

        resource = constants.VAULT_AUTH_ENDPOINT
        service = 'azure.keyvault.secrets'
        client = 'SecretClient'
        enum_spec = (None, 'list_properties_of_secrets', None)

        parent_manager_name = 'keyvault'
        raise_on_exception = False

        id = 'sid'

        default_report_fields = (
            'sid',
            'attributes.enabled',
            'attributes.exp',
            'attributes.recoveryLevel'
        )

        keyvault_child = True

    def augment(self, resources):
        resources = super(KeyVaultSecrets, self).augment(resources)
        # When KeyVault contains certificates, it creates corresponding key and secret objects to
        # store cert data. They are managed by KeyVault it is not possible to do any actions.
        return [r for r in resources if not r.get('managed')]


# @KeyVaultKeys.filter_registry.register('keyvault')
# class KeyVaultFilter(Filter):
#     schema = type_schema(
#         'keyvault',
#         required=['vaults'],
#         **{
#             'vaults': {'type': 'array', 'items': {'type': 'string'}}
#         }
#     )

#     def process(self, resources, event=None):
#         parent_key = self.manager.resource_type.parent_key
#         return [r for r in resources
#                 if ResourceIdParser.get_resource_name(r[parent_key]) in self.data['vaults']]


# @KeyVaultKeys.filter_registry.register('key-type')
# class KeyTypeFilter(Filter):
#     schema = type_schema(
#         'key-type',
#         **{
#             'key-types': {'type': 'array', 'items': {'enum': ['EC', 'EC-HSM', 'RSA', 'RSA-HSM']}}
#         }
#     )

#     def process(self, resources, event=None):

#         resources, _ = ThreadHelper.execute_in_parallel(
#             resources=resources,
#             event=event,
#             execution_method=self._process_resource_set,
#             executor_factory=self.executor_factory,
#             log=log
#         )
#         return resources

#     def _process_resource_set(self, resources, event):
#         matched = []
#         for resource in resources:
#             try:
#                 if 'c7n:kty' not in resource:
#                     id = KeyProperties(key_id=resource['id'])
#                     client = self.manager.get_client(vault_url=id.vault_url)
#                     key = client.get_key(id.name, id.version)

#                     resource['c7n:kty'] = key.key.kty.lower()

#                 if resource['c7n:kty'] in [t.lower() for t in self.data['key-types']]:
#                     matched.append(resource)
#             except Exception as error:
#                 log.warning(error)

#         return matched
