# Copyright The Cloud Custodian Authors.
# SPDX-License-Identifier: Apache-2.0

import logging
import uuid

from c7n_azure.provider import resources
from c7n_azure.resources.arm import ArmResourceManager
from c7n_azure.utils import StringUtils, PortsRangeHelper
from azure.core.exceptions import AzureError
from c7n_azure.utils import ThreadHelper

from c7n.actions import BaseAction
from c7n.filters import Filter, FilterValidationError
from c7n.filters.core import PolicyValidationError
from c7n.utils import type_schema

log = logging.getLogger('custodian.azure.network_security_group')

@resources.register('networksecuritygroup')
class NetworkSecurityGroup(ArmResourceManager):
    """Network Security Group Resource

    :example:

    This policy will deny access to all ports that are NOT 22, 23 or 24
    for all Network Security Groups

    .. code-block:: yaml

          policies:
           - name: close-inbound-except-22-24
             resource: azure.networksecuritygroup
             filters:
              - type: ingress
                exceptPorts: '22-24'
                match: 'any'
                access: 'Allow'
             actions:
              - type: close
                exceptPorts: '22-24'
                direction: 'Inbound'

    :example:

    This policy will find all NSGs with port 80 opened and port 443 closed,
    then it will open port 443

    .. code-block:: yaml

         policies:
           - name: close-egress-except-TCP
             resource: azure.networksecuritygroup
             filters:
              - type: ingress
                ports: '80'
                access: 'Allow'
              - type: ingress
                ports: '443'
                access: 'Deny'
             actions:
              - type: open
                ports: '443'


    :example:

    This policy will find all NSGs with port 22 opened from 'Any' source

    .. code-block:: yaml

         policies:
           - name: find-ingress-SSH-from-any-source
             resource: azure.networksecuritygroup
             filters:
              - type: ingress
                ports: '22'
                access: 'Allow'
                source: '*'


    :example:

    This policy will find all NSGs with port 8080 enabled to 'Any' destination

    .. code-block:: yaml

         policies:
           - name: find-egress-HTTP-to-any-destination
             resource: azure.networksecuritygroup
             filters:
              - type: egress
                ports: '8080'
                access: 'Allow'
                destination: '*'

    """

    class resource_type(ArmResourceManager.resource_type):
        doc_groups = ['Networking']

        service = 'azure.mgmt.network'
        client = 'NetworkManagementClient'
        enum_spec = ('network_security_groups', 'list_all', None)
        resource_type = 'Microsoft.Network/networkSecurityGroups'


DIRECTION = 'direction'
PORTS = 'ports'
MATCH = 'match'
EXCEPT_PORTS = 'exceptPorts'
IP_PROTOCOL = 'ipProtocol'
ACCESS = 'access'
PREFIX = 'prefix'

ALLOW_OPERATION = 'Allow'
DENY_OPERATION = 'Deny'

PRIORITY_STEP = 10

SOURCE = 'source'
DESTINATION = 'destination'


class NetworkSecurityGroupFilter(Filter):
    """
    Filter Network Security Groups using opened/closed ports configuration
    """

    schema = {
        'type': 'object',
        'properties': {
            'type': {'enum': []},
            MATCH: {'type': 'string', 'enum': ['all', 'any']},
            PORTS: {'type': 'string'},
            EXCEPT_PORTS: {'type': 'string'},
            IP_PROTOCOL: {'type': 'string', 'enum': ['TCP', 'UDP', '*']},
            ACCESS: {'type': 'string', 'enum': [ALLOW_OPERATION, DENY_OPERATION]},
            SOURCE: {'type': 'string'},
            DESTINATION: {'type': 'string'},
        },
        'required': ['type', ACCESS]
    }

    def validate(self):
        # Check that variable values are valid

        if PORTS in self.data:
            if not PortsRangeHelper.validate_ports_string(self.data[PORTS]):
                raise FilterValidationError("ports string has wrong format.")

        if EXCEPT_PORTS in self.data:
            if not PortsRangeHelper.validate_ports_string(self.data[EXCEPT_PORTS]):
                raise FilterValidationError("exceptPorts string has wrong format.")
        return True

    def process(self, network_security_groups, event=None):
        # Get variables
        self.ip_protocol = self.data.get(IP_PROTOCOL, '*')
        self.IsAllowed = StringUtils.equal(self.data.get(ACCESS), ALLOW_OPERATION)
        self.match = self.data.get(MATCH, 'all')

        # Calculate ports from the settings:
        #   If ports not specified -- assuming the entire range
        #   If except_ports not specifed -- nothing
        ports_set = PortsRangeHelper.get_ports_set_from_string(self.data.get(PORTS, '0-65535'))
        except_set = PortsRangeHelper.get_ports_set_from_string(self.data.get(EXCEPT_PORTS, ''))
        self.ports = ports_set.difference(except_set)
        self.source_address = self.data.get(SOURCE, None)
        self.destination_address = self.data.get(DESTINATION, None)

        nsgs = [nsg for nsg in network_security_groups if self._check_nsg(nsg)]
        return nsgs

    def _check_nsg(self, nsg):
        nsg_ports = PortsRangeHelper.build_ports_dict(nsg, self.direction_key, self.ip_protocol,
                                                      self.source_address,
                                                      self.destination_address)

        num_allow_ports = len([p for p in self.ports if nsg_ports.get(p)])
        num_deny_ports = len(self.ports) - num_allow_ports

        if self.match == 'all':
            if self.IsAllowed:
                return num_deny_ports == 0
            else:
                return num_allow_ports == 0
        if self.match == 'any':
            if self.IsAllowed:
                return num_allow_ports > 0
            else:
                return num_deny_ports > 0


@NetworkSecurityGroup.filter_registry.register('ingress')
class IngressFilter(NetworkSecurityGroupFilter):
    direction_key = 'Inbound'
    schema = type_schema('ingress', rinherit=NetworkSecurityGroupFilter.schema)


@NetworkSecurityGroup.filter_registry.register('egress')
class EgressFilter(NetworkSecurityGroupFilter):
    direction_key = 'Outbound'
    schema = type_schema('egress', rinherit=NetworkSecurityGroupFilter.schema)


@NetworkSecurityGroup.filter_registry.register('security-rule')
class SecurityRuleFilter(Filter):
    """
    Filter NSG's by a security rule.

    :example:

    Find NSG's allowing RDP access over the internet.

    .. code-block:: yaml

        policies:
          - name: networksecuritygroup-rdp-access
            resource: azure.networksecuritygroup
            filters:
              - type: security-rule
                access: "Allow"
                destinationPortRange: 
                    -"3389"
                    -"*"
                    -"contains:3389"
                direction: "Inbound"
                protocol: "TCP"
                sourceAddressPrefix: 
                    -"*"
                    -"0.0.0.0"
                    -"<nw>/0"
                    -"/0"
                    "internet"
                    "any"

    """

    schema = type_schema(
        'security-rule',
        protocol={'type': 'string'},
        sourcePortRange={'type': 'string'},
        destinationPortRange={'type': 'string'},
        sourceAddressPrefix={'type': 'string'},
        # sourceAddressPrefixes={'type': 'array'},
        destinationAddressPrefix={'type': 'string'},
        # destinationAddressPrefixes={'type': 'array'},
        # sourcePortRanges={'type': 'array'},
        # destinationPortRanges={'type': 'array'},
        access={'type': 'string'},
        priority={'type': 'number'},
        direction={'type': 'string'},
        provisioningState={'type': 'string'},
        includeDefaultRules={'type': 'boolean'}
        )

    log = logging.getLogger('custodian.azure.network_security_group.security-rule')

    def __init__(self, data, manager=None):
        super(SecurityRuleFilter, self).__init__(data, manager)
        # self.protocol = self.data.get('protocol', None)
        # self.sourcePortRange = self.data.get('sourcePortRange', None)
        # self.destinationPortRange = self.data.get('destinationPortRange', None)
        # self.sourceAddressPrefix = self.data.get('sourceAddressPrefix', None)
        # self.sourceAddressPrefixes = self.data.get('sourceAddressPrefixes', None)
        # self.destinationAddressPrefix = self.data.get('destinationAddressPrefix', None)
        # self.destinationAddressPrefixes = self.data.get('destinationAddressPrefixes', None)
        # self.sourcePortRanges = self.data.get('sourcePortRanges', None)
        # self.destinationPortRanges = self.data.get('destinationPortRanges', None)
        # self.access = self.data.get('access', None)
        # self.priority = self.data.get('priority', None)
        # self.direction = self.data.get('direction', None)
        # self.provisioningState = self.data.get('provisioningState', None)
        # self.includeDefaultRules = self.data.get('includeDefaultRules', False)

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
        result = []
        for resource in resources:
            securityRules = resource['properties']['securityRules']
            if not securityRules:
                continue
            for rule in securityRules:
                ruleProperties = rule['properties']
                isMatch = True
                for condition, filterValue in self.data.items():
                    if filterValue is None or condition == "includeDefaultRules" or condition == 'type':
                        continue

                    actualValue = ruleProperties.get(condition, None)
                    if actualValue is None:
                        actualValue = ruleProperties.get(condition+'s')
                    # should users be allowed to pass in an array (i.e. sourcePortRanges) or just one value per filter, otherwise the checking gets complicated
                    if (isinstance(actualValue, list) and filterValue not in actualValue) or filterValue != actualValue:
                    # if (isinstance(filterValue, list) and not (set(filterValue).intersection(set(actualValue)))) \
                    #     or filterValue != actualValue \
                    #         or 
                            isMatch = False
                            break
                if isMatch:
                    result.append(resource)
                    break
        return result


class NetworkSecurityGroupPortsAction(BaseAction):
    """
    Action to perform on Network Security Groups
    """

    schema = {
        'type': 'object',
        'properties': {
            'type': {'enum': []},
            PORTS: {'type': 'string'},
            EXCEPT_PORTS: {'type': 'string'},
            IP_PROTOCOL: {'type': 'string', 'enum': ['TCP', 'UDP', '*']},
            DIRECTION: {'type': 'string', 'enum': ['Inbound', 'Outbound']},
            PREFIX: {'type': 'string', 'maxLength': 44}  # 80 symbols limit, guid takes 36
        },
        'required': ['type', DIRECTION]
    }

    def validate(self):
        # Check that variable values are valid

        if PORTS in self.data:
            if not PortsRangeHelper.validate_ports_string(self.data[PORTS]):
                raise PolicyValidationError("ports string has wrong format.")

        if EXCEPT_PORTS in self.data:
            if not PortsRangeHelper.validate_ports_string(self.data[EXCEPT_PORTS]):
                raise PolicyValidationError("exceptPorts string has wrong format.")
        return True

    def _build_ports_strings(self, nsg, direction_key, ip_protocol):
        nsg_ports = PortsRangeHelper.build_ports_dict(nsg, direction_key, ip_protocol)

        IsAllowed = StringUtils.equal(self.access_action, ALLOW_OPERATION)

        # Find ports with different access level from NSG and this action
        diff_ports = sorted([p for p in self.action_ports if nsg_ports.get(p, False) != IsAllowed])

        return PortsRangeHelper.get_ports_strings_from_list(diff_ports)

    def process(self, network_security_groups):

        ip_protocol = self.data.get(IP_PROTOCOL, '*')
        direction = self.data[DIRECTION]
        prefix = self.data.get(PREFIX, 'c7n-policy-')
        # Build a list of ports described in the action.
        ports = PortsRangeHelper.get_ports_set_from_string(self.data.get(PORTS, '0-65535'))
        except_ports = PortsRangeHelper.get_ports_set_from_string(self.data.get(EXCEPT_PORTS, ''))
        self.action_ports = ports.difference(except_ports)

        for nsg in network_security_groups:
            nsg_name = nsg['name']
            resource_group = nsg['resourceGroup']

            # Get list of ports to Deny or Allow access to.
            ports = self._build_ports_strings(nsg, direction, ip_protocol)
            if not ports:
                # If its empty, it means NSG already blocks/allows access to all ports,
                # no need to change.
                self.manager.log.info("Network security group %s satisfies provided "
                                      "ports configuration, no actions scheduled.", nsg_name)
                continue

            rules = nsg['properties']['securityRules']
            rules = sorted(rules, key=lambda k: k['properties']['priority'])
            rules = [r for r in rules
                     if StringUtils.equal(r['properties']['direction'], direction)]
            lowest_priority = rules[0]['properties']['priority'] if len(rules) > 0 else 4096

            # Create new top-priority rule to allow/block ports from the action.
            rule_name = prefix + str(uuid.uuid1())
            new_rule = {
                'name': rule_name,
                'properties': {
                    'access': self.access_action,
                    'destinationAddressPrefix': '*',
                    'destinationPortRanges': ports,
                    'direction': self.data[DIRECTION],
                    'priority': lowest_priority - PRIORITY_STEP,
                    'protocol': ip_protocol,
                    'sourceAddressPrefix': '*',
                    'sourcePortRange': '*',
                }
            }
            self.manager.log.info("NSG %s. Creating new rule to %s access for ports %s",
                                  nsg_name, self.access_action, ports)

            try:
                self.manager.get_client().security_rules.begin_create_or_update(
                    resource_group,
                    nsg_name,
                    rule_name,
                    new_rule
                )
            except AzureError as e:
                self.manager.log.error('Failed to create or update security rule for %s NSG.',
                                       nsg_name)
                self.manager.log.error(e)


@NetworkSecurityGroup.action_registry.register('close')
class CloseRules(NetworkSecurityGroupPortsAction):
    """
    Deny access to Security Rule
    """
    schema = type_schema('close', rinherit=NetworkSecurityGroupPortsAction.schema)
    access_action = DENY_OPERATION


@NetworkSecurityGroup.action_registry.register('open')
class OpenRules(NetworkSecurityGroupPortsAction):
    """
    Allow access to Security Rule
    """
    schema = type_schema('open', rinherit=NetworkSecurityGroupPortsAction.schema)
    access_action = ALLOW_OPERATION
