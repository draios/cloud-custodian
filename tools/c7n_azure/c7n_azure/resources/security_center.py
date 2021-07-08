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
    )

    log = logging.getLogger('custodian.azure.security-center.auto-provisioning-settings')

    def __init__(self, data, manager=None):
        super(AutoProvisioningSettingsFilter, self).__init__(data, manager)

    def process(self, resources, event=None):
        client = self.manager.get_client()

        settings_iterator = client.auto_provisioning_settings.list()
        settings_list = []
        while True:
            try:
                settings_list.append(settings_iterator.next().serialize(True))
            except StopIteration:
                break

        return settings_list
