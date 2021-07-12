# Copyright The Cloud Custodian Authors.
# SPDX-License-Identifier: Apache-2.0

import logging
from c7n_azure.constants import RESOURCE_GROUPS_TYPE
from c7n_azure.provider import resources
from c7n_azure.query import DescribeSource, ResourceQuery
from c7n_azure.resources.arm import ArmResourceManager

from c7n.filters.core import Filter, type_schema
from c7n.query import sources
from c7n_azure.utils import ResourceIdParser, is_resource_group_id
from c7n_azure.utils import ThreadHelper
from c7n_azure.filters import DiagnosticSettingsFilter

log = logging.getLogger('custodian.azure.generic_arm_resource')


class GenericArmResourceQuery(ResourceQuery):

    def filter(self, resource_manager, **params):
        client = resource_manager.get_client()
        results = [r.serialize(True) for r in client.resources.list()]

        resource_groups = [r.serialize(True) for r in client.resource_groups.list()]
        for r in resource_groups:
            r['type'] = RESOURCE_GROUPS_TYPE
        results.extend(resource_groups)

        return results


@sources.register('describe-azure-generic')
class GenericArmDescribeSource(DescribeSource):

    resource_query_factory = GenericArmResourceQuery


@resources.register('armresource')
class GenericArmResource(ArmResourceManager):
    """Azure Arm Resource

    :example:

    This policy will find all ARM resources with the tag 'Tag1' present

    .. code-block:: yaml

        policies
          - name: find-resources-with-Tag1
            resource: azure.armresource
            filters:
              - tag:Tag1: present

    """

    class resource_type(ArmResourceManager.resource_type):
        doc_groups = ['Generic']

        service = 'azure.mgmt.resource'
        client = 'ResourceManagementClient'

        resource_type = 'armresource'
        diagnostic_settings_enabled = False

        default_report_fields = (
            'name',
            'type',
            'location',
            'resourceGroup'
        )

    def get_resources(self, resource_ids):
        client = self.get_client()
        result = []

        for rid in resource_ids:
            resource = None
            if is_resource_group_id(rid):
                resource = client.resource_groups.get(ResourceIdParser.get_resource_group(rid))
                resource.type = RESOURCE_GROUPS_TYPE
            else:
                resource = client.resources.get_by_id(rid, self._session.resource_api_version(rid))
            result.append(resource)

        return self.augment([r.serialize(True) for r in result])

    @property
    def source_type(self):
        return self.data.get('source', 'describe-azure-generic')


@GenericArmResource.filter_registry.register('resource-type')
class ResourceTypeFilter(Filter):
    schema = type_schema('resource-type',
                         required=['values'],
                         values={'type': 'array', 'items': {'type': 'string'}})

    def __init__(self, data, manager=None):
        super(ResourceTypeFilter, self).__init__(data, manager)
        self.allowed_types = [t.lower() for t in self.data['values']]

    def process(self, resources, event=None):
        result = []
        for r in resources:
            if r['type'].lower() in self.allowed_types:
                result.append(r)

        return result


@GenericArmResource.filter_registry.register('diagnostic-setting')
class DiagnosticSettingFilter(Filter):
    schema = type_schema(
        'diagnostic-setting',
        required=['type', 'enabled'],
        **{
            'enabled': {"type": "boolean"},
        }
    )

    log = logging.getLogger('custodian.azure.generic_arm_resource.diagnostic-setting-filter')

    def __init__(self, data, manager=None):
        super(DiagnosticSettingFilter, self).__init__(data, manager)
        self.enabled = self.data['enabled']

    def process(self, resources, event=None):
        resources, exceptions = ThreadHelper.execute_in_parallel(
            resources=resources,
            event=event,
            execution_method=self._process_resource_set,
            executor_factory=self.executor_factory,
            log=log
        )
        if exceptions:
            raise exceptions[0]
        return resources

    def _process_resource_set(self, resources, event=None):
        diagnostic = DiagnosticSettingsFilter(self.data)
        log.debug(diagnostic)
        result = diagnostic.process_resource_set(resources)
        if self.enabled:
            return result
        resources = set(resources)
        result = set(result)
        return list(resources.difference(result))
