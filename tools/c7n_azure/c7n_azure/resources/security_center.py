from c7n_azure.provider import resources
from c7n_azure.resources.arm import ArmResourceManager

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