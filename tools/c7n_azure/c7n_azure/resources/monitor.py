import logging
from c7n.filters.core import Filter
from c7n.utils import type_schema
from c7n_azure.provider import resources
from c7n_azure.resources.arm import ArmResourceManager

log = logging.getLogger(__name__)


@resources.register('monitor')
class Monitor(ArmResourceManager):

    class resource_type(ArmResourceManager.resource_type):
        service = 'azure.mgmt.monitor'
        client = 'MonitorManagementClient'
        enum_spec = ('operations', 'list', None)
        resource_type = 'Microsoft.insights/diagnosticSettings'
        # enum_spec = ('subscription_diagnostic_settings', 'list',
        # {"subscription_id": "bfc31cc5-d3bd-4b36-a40e-d13688d546ec"})
        # resource_type = 'Microsoft.insights/diagnosticSettings'
        # default_report_fields = (
        #     'name',
        #     'location',
        #     'resourceGroup',
        #     'sku.name
        # )


@Monitor.filter_registry.register('subscription-diagnostic-settings')
class SubscriptionDiagnosticSettingsFilter(Filter):
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
        'subscription-diagnostic-settings',
        required=['type', 'subscriptionId'],
        **{
            'subscriptionId': {"type": "string"},
        }
    )

    log = logging.getLogger('custodian.azure.monitor.subscription-diagnostic-settings')

    def __init__(self, data, manager=None):
        super(SubscriptionDiagnosticSettingsFilter, self).__init__(data, manager)
        self.id = self.data['subscriptionId']

    def process(self, resources, event=None):
        client = self.manager.get_client()
        return client.subscription_diagnostic_settings.list(self.id).serialize(True)
        # resources, exceptions = ThreadHelper.execute_in_parallel(
        #     resources=resources,
        #     event=event,
        #     execution_method=self._process_resource_set,
        #     executor_factory=self.executor_factory,
        #     log=log
        # )
        # if exceptions:
        #     raise exceptions[0]
        # return resources

    # def _process_resource_set(self, resources, event=None):
    #     client = self.manager.get_client()
    #     result = []
    #     for resource in resources:
    #         settings = client.subscription_diagnostic_settings.list(self.id)
    #         result.append(settings)

    #     return result


@Monitor.filter_registry.register('log-profiles')
class LogProfilesFilter(Filter):
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
        'log-profiles'
        # required=['type', 'subscriptionId'],
        # **{
        #     'subscriptionId': {"type": "string"},
        # }
    )

    log = logging.getLogger('custodian.azure.monitor.log-profiles')

    def __init__(self, data, manager=None):
        super(LogProfilesFilter, self).__init__(data, manager)

    def process(self, resources, event=None):
        client = self.manager.get_client()
        log_profiles_iterator = client.log_profiles.list().by_page()
        while True:
            try:
                log.debug(log_profiles_iterator.next())
            except StopIteration:
                break

        return []
