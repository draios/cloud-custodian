from c7n_azure.provider import resources
from c7n_azure.resources.arm import ArmResourceManager
from c7n.filters.core import ValueFilter, type_schema

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

@SecurityCenter.filter_registry.register('auth-provisioning-settings')
class ServerAuditingFilter(ValueFilter):
    """
    Provides a value filter targeting the auditing policy of this
    SQL Server.

    Here is an example of the available fields:

    .. code-block:: json

      "state": "Enabled",
      "storageEndpoint": "https://yourstorageendpoint.blob.core.windows.net/",
      "retentionDays": 0,
      "auditActionsAndGroups": [
          "SUCCESSFUL_DATABASE_AUTHENTICATION_GROUP",
          "FAILED_DATABASE_AUTHENTICATION_GROUP",
          "BATCH_COMPLETED_GROUP"
        ]

    :examples:

    Find SQL Servers with failed database login auditing enabled

    .. code-block:: yaml

        policies:
          - name: sqlserver-failed-login-audit
            resource: azure.sqlserver
            filters:
              - type: uditing-policy
                key: "auditActionsAndGroups"
                op: contains
                value: "FAILED_DATABASE_AUTHENTICATION_GROUP"

    """

    schema = type_schema('auth-provisioning-settings', rinherit=ValueFilter.schema)

    def __call__(self, i):
        client = self.manager.get_client()
        settings = list(
            client.auth_provisioning_settings
            .list()
        )

        return settings