from c7n.exceptions import PolicyValidationError
import logging, os
from c7n.filters.core import ValueFilter
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


@resources.register('alerts')
class Alert(ArmResourceManager):

    class resource_type(ArmResourceManager.resource_type):
        service = 'azure.mgmt.alertsmanagement'
        client = 'AlertsManagementClient'
        enum_spec = ('alerts', 'get_all', None)


@resources.register('subscription-diagnostic-settings')
class SubscriptionDiagnosticSettings(ArmResourceManager):

    class resource_type(ArmResourceManager.resource_type):
        service = 'azure.mgmt.monitor'
        client = 'MonitorManagementClient'
        enum_spec = ('subscription_diagnostic_settings', 'list',
        {'subscription_id': os.getenv("AZURE_SUBSCRIPTION_ID")})
        resource_type = 'Microsoft.insights/diagnosticSettings'


@resources.register('subscription-log-profiles')
class SubscriptionLogProfiles(ArmResourceManager):

    class resource_type(ArmResourceManager.resource_type):
        service = 'azure.mgmt.monitor'
        client = 'MonitorManagementClient'
        enum_spec = ('log_profiles', 'list', None)
        resource_type = 'Microsoft.insights/diagnosticSettings'


@SubscriptionDiagnosticSettings.filter_registry.register('logs')
class LogsFilter(ValueFilter):
    """

    """

    log_schema = {
        'type': 'object',
        # Doesn't mix well with inherits that extend
        'additionalProperties': False,
        'required': ['category', 'enabled'],
        'properties': {
            # Doesn't mix well as enum with inherits that extend
            'type': {'enum': ['value']},
            'category': {'type': 'string'},
            'enabled': {'type': 'boolean'},
        }
    }
    schema = type_schema('logs', rinherit=log_schema)

    log = logging.getLogger('custodian.azure.monitor.logs')

    def __init__(self, data, manager=None):
        if 'category' not in data:
            raise PolicyValidationError('Missing category in log filter')
        if 'enabled' not in data:
            raise PolicyValidationError('Missing enabled in log filter')
        data['key'] = data['category']
        data['value'] = data['enabled']
        super(LogsFilter, self).__init__(data, manager)

    def process(self, resources, event=None):
        r = resources[0]
        logs = r['properties'].get('logs', [])
        if not isinstance(logs, dict):
            logMap = {}
            for log in logs:
                logMap[log['category']] = log['enabled']
            r['properties']['logs'] = logMap

        resources = [r]
        return super(LogsFilter, self).process(resources, event=None)

    def __call__(self, r):
        return self.match(r['properties']['logs'])
