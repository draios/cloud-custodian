# Copyright The Cloud Custodian Authors.
# SPDX-License-Identifier: Apache-2.0

from c7n.filters.core import ValueFilter
from c7n.utils import type_schema
from c7n_azure.provider import resources
from c7n_azure.resources.arm import ArmResourceManager
from c7n_azure.filters import FirewallRulesFilter
from netaddr import IPRange, IPSet

import logging

AZURE_SERVICES = IPRange('0.0.0.0', '0.0.0.0')  # nosec

logger = logging.getLogger(__name__)


@resources.register('postgresql-server')
class PostgresqlServer(ArmResourceManager):
    """PostgreSQL Server Resource

    :example:

    Finds all PostgreSQL Servers that have had zero active connections in the past week

    .. code-block:: yaml

        policies:
          - name: find-all-unused-postgresql-servers
            resource: azure.postgresql-server
            filters:
              - type: metric
                metric: active_connections
                op: eq
                threshold: 0
                timeframe: 168

    :example:

    Finds all PostgreSQL Servers that cost more than 1000 in the last month

    .. code-block:: yaml

        policies:
          - name: find-all-costly-postgresql-servers
            resource: azure.postgresql-server
            filters:
              - type: cost
                key: TheLastMonth
                op: gt
                value: 1000

    """

    class resource_type(ArmResourceManager.resource_type):
        doc_groups = ['Databases']

        service = 'azure.mgmt.rdbms.postgresql'
        client = 'PostgreSQLManagementClient'
        enum_spec = ('servers', 'list', None)
        resource_type = 'Microsoft.DBforPostgreSQL/servers'


@PostgresqlServer.filter_registry.register('firewall-rules')
class PostgresqlServerFirewallRulesFilter(FirewallRulesFilter):
    def _query_rules(self, resource):
        query = self.client.firewall_rules.list_by_server(
            resource['resourceGroup'],
            resource['name'])
        resource_rules = IPSet()
        for r in query:
            rule = IPRange(r.start_ip_address, r.end_ip_address)
            if rule == AZURE_SERVICES:
                # Ignore 0.0.0.0 magic value representing Azure Cloud bypass
                continue
            resource_rules.add(rule)
        return resource_rules


@PostgresqlServer.filter_registry.register('server-parameters')
class PostgresqlServerParametersFilter(ValueFilter):
    schema = type_schema('server-parameters', rinherit=ValueFilter.schema)

    def __call__(self, i):
        if 'server_parameters' not in i['properties']:
            client = self.manager.get_client()
            params = list(
                client.configurations
                    .list_by_server(i['resourceGroup'], i['name'])
            )

            i['properties']['server_parameters'] = {}
            if params:
                for parameter in params:
                    i['properties']['server_parameters'][parameter.serialize(True).get('name')] \
                        = parameter.serialize(True).get('properties', {}).get("value", None)

        return super(PostgresqlServerParametersFilter,
                     self).__call__(i['properties']['server_parameters'])
