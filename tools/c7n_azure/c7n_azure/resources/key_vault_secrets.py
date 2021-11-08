# Copyright The Cloud Custodian Authors.
# SPDX-License-Identifier: Apache-2.0

import logging

from c7n_azure import constants
from c7n_azure.provider import resources
from c7n_azure.query import ChildResourceManager, ChildTypeInfo

log = logging.getLogger('custodian.azure.keyvault.keys')


@resources.register('keyvault-secret', aliases=['keyvault-secrets'])
class KeyVaultSecrets(ChildResourceManager):
    """Key Vault Secret Resource

    :example:

    This policy will find all KeyVaults with an expiration time set

    .. code-block:: yaml

        policies:
          - name: keyvault-secrets-expiration
            resource: azure.keyvault-secrets
            filters:
              - type: value
                key: "attributes.expires"
                value: present

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
