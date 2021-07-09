from tools.c7n_azure.c7n_azure.resources.subscription import Subscription
from c7n_azure.provider import resources
from c7n_azure.resources.arm import ArmResourceManager
from c7n.filters.core import Filter, ValueFilter, type_schema

import logging
log = logging.getLogger(__name__)

@resources.register('security-center')
class SecurityCenter(ArmResourceManager):

    class resource_type(ArmResourceManager.resource_type):
        service = 'azure.mgmt.security'
        client = 'SecurityCenter'
        enum_spec = ('settings', 'list', None)
        # default_report_fields = (
        #     'name',
        #     'location',
        #     'resourceGroup',
        #     'sku.name
        # )
        resource_type = 'Microsoft.Security/SecurityCenter'

@SecurityCenter.filter_registry.register('auto-provisioning-settings')
class AutoProvisioningSettingsFilter(Filter):
    """
    Filter sql servers by whether they have recurring vulnerability scans
    enabled.

    :example:

    Find SQL servers without vulnerability assessments enabled.

    .. code-block:: yaml

        policies:
          - name: sql-server-no-va
            resource: azure.sql-server
            filters:
              - type: vulnerability-assessment
                enabled: false

    """

    schema = type_schema(
        'auto-provisioning-settings',
        required=['type', 'enabled'],
        **{
            'enabled': {"type": "boolean"},
        }
    )

    log = logging.getLogger('custodian.azure.security-center.auto-provisioning-settings')

    def __init__(self, data, manager=None):
        super(AutoProvisioningSettingsFilter, self).__init__(data, manager)
        self.enabled = self.data['enabled']

    def process(self, resources, event=None):
        client = self.manager.get_client()

        settings_iterator = client.auto_provisioning_settings.list()
        settings_list = []
        while True:
            try:
                setting = settings_iterator.next().serialize(True)
                autoProvisionStatus = setting['properties']['autoProvision']
                if (autoProvisionStatus == "On" and self.enabled) or (autoProvisionStatus == "Off" and not self.enabled):
                    settings_list.append(setting)
            except StopIteration:
                break

        return settings_list

@SecurityCenter.filter_registry.register('security-contacts')
class SecurityContactsFilter(Filter):
    """
    Filter sql servers by whether they have recurring vulnerability scans
    enabled.

    :example:

    Find SQL servers without vulnerability assessments enabled.

    .. code-block:: yaml

        policies:
          - name: sql-server-no-va
            resource: azure.sql-server
            filters:
              - type: vulnerability-assessment
                enabled: false

    """

    schema = type_schema(
        'security-contacts',
        required=['type', 'enabled'],
        **{
            'enabled': {"type": "boolean"},
        }
    )

    log = logging.getLogger('custodian.azure.security-center.security-contacts')

    def __init__(self, data, manager=None):
        super(SecurityContactsFilter, self).__init__(data, manager)
        self.enabled = self.data['enabled']

    def process(self, resources, event=None):
        client = self.manager.get_client()

        settings_iterator = client.security_contacts.list()
        settings_list = []
        while True:
            try:
                setting = settings_iterator.next().serialize(True)
                email = setting['properties']['email']
                if (email and self.enabled) or (not email and not self.enabled):
                    settings_list.append(setting)
            except StopIteration:
                break
            
        return settings_list
