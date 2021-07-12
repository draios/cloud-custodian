# Copyright The Cloud Custodian Authors.
# SPDX-License-Identifier: Apache-2.0
ResourceMap = {
    "azure.aks": "c7n_azure.resources.k8s_service.KubernetesService",
    "azure.api-management": "c7n_azure.resources.apimanagement.ApiManagement",
    "azure.appserviceplan": "c7n_azure.resources.appserviceplan.AppServicePlan",
    "azure.armresource": "c7n_azure.resources.generic_arm_resource.GenericArmResource",
    "azure.batch": "c7n_azure.resources.batch.Batch",
    "azure.cdnprofile": "c7n_azure.resources.cdn.CdnProfile",
    "azure.cognitiveservice": "c7n_azure.resources.cognitive_service.CognitiveService",
    "azure.container-group": "c7n_azure.resources.aci.ContainerGroup",
    "azure.containerregistry": "c7n_azure.resources.container_registry.ContainerRegistry",
    "azure.container-registry": "c7n_azure.resources.container_registry.ContainerRegistry",
    "azure.containerservice": "c7n_azure.resources.container_service.ContainerService",
    "azure.cosmosdb": "c7n_azure.resources.cosmos_db.CosmosDB",
    "azure.cosmosdb-collection": "c7n_azure.resources.cosmos_db.CosmosDBCollection",
    "azure.cosmosdb-database": "c7n_azure.resources.cosmos_db.CosmosDBDatabase",
    "azure.cost-management-export": "c7n_azure.resources.cost_management_export.CostManagementExport",  # noqa
    "azure.databricks": "c7n_azure.resources.databricks.Databricks",
    "azure.datafactory": "c7n_azure.resources.data_factory.DataFactory",
    "azure.datalake": "c7n_azure.resources.datalake_store.DataLakeStore",
    "azure.disk": "c7n_azure.resources.disk.Disk",
    "azure.dnszone": "c7n_azure.resources.dns_zone.DnsZone",
    "azure.eventhub": "c7n_azure.resources.event_hub.EventHub",
    "azure.eventsubscription": "c7n_azure.resources.event_subscription.EventSubscription",
    "azure.hdinsight": "c7n_azure.resources.hdinsight.Hdinsight",
    "azure.image": "c7n_azure.resources.image.Image",
    "azure.iothub": "c7n_azure.resources.iot_hub.IoTHub",
    "azure.keyvault": "c7n_azure.resources.key_vault.KeyVault",
    "azure.keyvault-certificate": "c7n_azure.resources.key_vault_certificate.KeyVaultCertificate",
    "azure.keyvault-key": "c7n_azure.resources.key_vault_keys.KeyVaultKeys",
    "azure.keyvault-keys": "c7n_azure.resources.key_vault_keys.KeyVaultKeys",
    "azure.keyvault-secret": "c7n_azure.resources.key_vault_secrets.KeyVaultSecrets",
    "azure.keyvault-secrets": "c7n_azure.resources.key_vault_secrets.KeyVaultSecrets",
    "azure.loadbalancer": "c7n_azure.resources.load_balancer.LoadBalancer",
    "azure.networkinterface": "c7n_azure.resources.network_interface.NetworkInterface",
    "azure.networksecuritygroup": "c7n_azure.resources.network_security_group.NetworkSecurityGroup",
    "azure.policyassignments": "c7n_azure.resources.policy_assignments.PolicyAssignments",
    "azure.postgresql-database": "c7n_azure.resources.postgresql_database.PostgresqlDatabase",
    "azure.postgresql-server": "c7n_azure.resources.postgresql_server.PostgresqlServer",
    "azure.publicip": "c7n_azure.resources.public_ip.PublicIPAddress",
    "azure.recordset": "c7n_azure.resources.record_set.RecordSet",
    "azure.redis": "c7n_azure.resources.redis.Redis",
    "azure.resourcegroup": "c7n_azure.resources.resourcegroup.ResourceGroup",
    "azure.roleassignment": "c7n_azure.resources.access_control.RoleAssignment",
    "azure.roledefinition": "c7n_azure.resources.access_control.RoleDefinition",
    "azure.routetable": "c7n_azure.resources.route_table.RouteTable",
    "azure.search": "c7n_azure.resources.search.SearchService",
    "azure.security-center": "c7n_azure.resources.security_center.SecurityCenter",
    "azure.sql-database": "c7n_azure.resources.sqldatabase.SqlDatabase",
    "azure.sqldatabase": "c7n_azure.resources.sqldatabase.SqlDatabase",
    "azure.sql-server": "c7n_azure.resources.sqlserver.SqlServer",
    "azure.sqlserver": "c7n_azure.resources.sqlserver.SqlServer",
    "azure.storage": "c7n_azure.resources.storage.Storage",
    "azure.storage-container": "c7n_azure.resources.storage_container.StorageContainer",
    "azure.subscription": "c7n_azure.resources.subscription.Subscription",
    "azure.vm": "c7n_azure.resources.vm.VirtualMachine",
    "azure.vmss": "c7n_azure.resources.vmss.VMScaleSet",
    "azure.vnet": "c7n_azure.resources.vnet.Vnet",
    "azure.webapp": "c7n_azure.resources.web_app.WebApp"
}
