# Copyright The Cloud Custodian Authors.
# SPDX-License-Identifier: Apache-2.0

import itertools
from tools.c7n_gcp.c7n_gcp.filters.iampolicy import IamPolicyFilter

from c7n_gcp.actions import SetIamPolicy, MethodAction
from c7n_gcp.provider import resources
from c7n_gcp.query import QueryResourceManager, TypeInfo

from c7n.filters.core import ValueFilter
from c7n.resolver import ValuesFrom
from c7n.utils import type_schema, local_session


@resources.register('organization')
class Organization(QueryResourceManager):
    """GCP resource: https://cloud.google.com/resource-manager/reference/rest/v1/organizations
    """
    class resource_type(TypeInfo):
        service = 'cloudresourcemanager'
        version = 'v1'
        component = 'organizations'
        scope = 'global'
        enum_spec = ('search', 'organizations[]', {'body': {}})
        id = 'name'
        name = 'displayName'
        default_report_fields = [
            "name", "displayName", "creationTime", "lifecycleState"]
        asset_type = "cloudresourcemanager.googleapis.com/Organization"
        scc_type = "google.cloud.resourcemanager.Organization"
        perm_service = 'resourcemanager'
        permissions = ('resourcemanager.organizations.get',)

        @staticmethod
        def get(client, resource_info):
            org = resource_info['resourceName'].rsplit('/', 1)[-1]
            return client.execute_query(
                'get', {'name': "organizations/" + org})


@Organization.action_registry.register('set-iam-policy')
class OrganizationSetIamPolicy(SetIamPolicy):
    """
    Overrides the base implementation to process Organization resources correctly.
    """
    def _verb_arguments(self, resource):
        verb_arguments = SetIamPolicy._verb_arguments(self, resource)
        verb_arguments['body'] = {}
        return verb_arguments


@resources.register('folder')
class Folder(QueryResourceManager):
    """GCP resource: https://cloud.google.com/resource-manager/reference/rest/v1/folders
    """
    class resource_type(TypeInfo):
        service = 'cloudresourcemanager'
        version = 'v2'
        component = 'folders'
        scope = 'global'
        enum_spec = ('list', 'folders', None)
        name = id = 'name'
        default_report_fields = [
            "name", "displayName", "lifecycleState", "createTime", "parent"]
        asset_type = "cloudresourcemanager.googleapis.com/Folder"
        perm_service = 'resourcemanager'

    def get_resources(self, resource_ids):
        client = self.get_client()
        results = []
        for rid in resource_ids:
            if not rid.startswith('folders/'):
                rid = 'folders/%s' % rid
            results.append(client.execute_query('get', {'name': rid}))
        return results

    def get_resource_query(self):
        if 'query' in self.data:
            for child in self.data.get('query'):
                if 'parent' in child:
                    return {'parent': child['parent']}


@resources.register('project')
class Project(QueryResourceManager):
    """GCP resource: https://cloud.google.com/compute/docs/reference/rest/v1/projects
    """
    class resource_type(TypeInfo):
        service = 'cloudresourcemanager'
        version = 'v1'
        component = 'projects'
        scope = 'global'
        enum_spec = ('list', 'projects', None)
        name = id = 'projectId'
        default_report_fields = [
            "name", "displayName", "lifecycleState", "createTime", "parent"]
        asset_type = "cloudresourcemanager.googleapis.com/Project"
        scc_type = "google.cloud.resourcemanager.Project"
        perm_service = 'resourcemanager'
        labels = True
        labels_op = 'update'

        @staticmethod
        def get_label_params(resource, labels):
            return {'projectId': resource['projectId'],
                    'body': {
                        'name': resource['name'],
                        'parent': resource['parent'],
                        'labels': labels}}

        @staticmethod
        def get(client, resource_info):
            return client.execute_query(
                'get', {'projectId': resource_info['resourceName'].rsplit('/', 1)[-1]})

    def get_resource_query(self):
        # https://cloud.google.com/resource-manager/reference/rest/v1/projects/list
        if 'query' in self.data:
            for child in self.data.get('query'):
                if 'filter' in child:
                    return {'filter': child['filter']}


@Project.filter_registry.register('iam-policy')
class ProjectIamPolicyFilter(IamPolicyFilter):
    """
    Overrides the base implementation to process Project resources correctly.
    """
    permissions = ('resourcemanager.projects.getIamPolicy',)

    def _verb_arguments(self, resource):
        verb_arguments = SetIamPolicy._verb_arguments(self, resource)
        verb_arguments['body'] = {}
        return verb_arguments


@Project.filter_registry.register('iam-user-roles')
class IamPolicyUserRoles(ValueFilter):
    """Filters a project by its IAM Policy's users and their assigned roles.

    :example:

    Filter all projects where the user test123@gmail.com is assigned the owner role

    .. code-block :: yaml

       policies:
        - name: gcp-iam-user-roles
          resource: gcp.project
          filters:
            - type: iam-user-roles
              key: "user:test123@gmail.com"
              op: contains
              value: "roles/owner"
    """

    schema = type_schema('iam-user-roles', rinherit=ValueFilter.schema)
    #     permissions = ('resourcemanager.projects.getIamPolicy',)

    def get_client(self, session, model):
        return session.client(
            model.service, model.version, model.component)

    def process(self, resources, event=None):
        model = self.manager.get_model()
        session = local_session(self.manager.session_factory)
        client = self.get_client(session, model)

        for r in resources:
            iam_policy = client.execute_command('getIamPolicy', {"resource": r["projectId"]})
            r["iamPolicyUserRoles"] = []
            userToRolesMap = {}

            for b in iam_policy["bindings"]:
                role, members = b["role"], b["members"]
                for user in members:
                    if user in userToRolesMap:
                        userToRolesMap[user].append(role)
                    else:
                        userToRolesMap[user] = [role]
            for user, roles in userToRolesMap.items():
                r["iamPolicyUserRoles"].append({"user": user, "roles": roles})

        return super(IamPolicyUserRoles, self).process(resources)

    def __call__(self, r):
        return self.match(r['iamPolicyUserRoles'])


@Project.filter_registry.register('iam-member-roles')
class IamPolicyMemberRoles(ValueFilter):
    """Filters a project by its IAM policy's member types and their assigned roles.

    :example:

    Filter all projects where at least one service account is assigned the owner role

    .. code-block :: yaml

       policies:
        - name: gcp-iam-member-roles
          resource: gcp.project
          filters:
            - type: iam-member-roles
              key: "serviceAccount"
              op: contains
              value: "roles/owner"
    """

    MEMBER_TYPES = ["user", "group", "serviceAccount", "domain"]
    schema = type_schema('iam-member-roles', rinherit=ValueFilter.schema)
    #     permissions = ('compute.instances.getEffectiveFirewalls',)

    def get_client(self, session, model):
        return session.client(
            model.service, model.version, model.component)

    def process(self, resources, event=None):
        model = self.manager.get_model()
        session = local_session(self.manager.session_factory)
        client = self.get_client(session, model)

        for r in resources:
            iam_policy = client.execute_command('getIamPolicy', {"resource": r["projectId"]})
            r["iamPolicyMemberRoles"] = {}
            memberToRoleMap = {m_type: set() for m_type in IamPolicyMemberRoles.MEMBER_TYPES}

            for b in iam_policy["bindings"]:
                role, members = b["role"], b["members"]
                for m_name in members:
                    for m_type in IamPolicyMemberRoles.MEMBER_TYPES:
                        if m_type in m_name:
                            memberToRoleMap[m_type].add(role)
                            break
            for m_type, roles in memberToRoleMap.items():
                r["iamPolicyMemberRoles"][m_type] = list(roles)

        return super(IamPolicyMemberRoles, self).process(resources)

    def __call__(self, r):
        return self.match(r['iamPolicyMemberRoles'])


@Project.action_registry.register('delete')
class ProjectDelete(MethodAction):
    """Delete a GCP Project

    Note this will also schedule deletion of assets contained within
    the project. The project will not be accessible, and assets
    contained within the project may continue to accrue costs within
    a 30 day period. For details see
    https://cloud.google.com/resource-manager/docs/creating-managing-projects#shutting_down_projects

    """
    method_spec = {'op': 'delete'}
    attr_filter = ('lifecycleState', ('ACTIVE',))
    schema = type_schema('delete')

    def get_resource_params(self, model, resource):
        return {'projectId': resource['projectId']}


@Project.action_registry.register('set-iam-policy')
class ProjectSetIamPolicy(SetIamPolicy):
    """
    Overrides the base implementation to process Project resources correctly.
    """
    def _verb_arguments(self, resource):
        verb_arguments = SetIamPolicy._verb_arguments(self, resource)
        verb_arguments['body'] = {}
        return verb_arguments


class HierarchyAction(MethodAction):

    def load_hierarchy(self, resources):
        parents = {}
        session = local_session(self.manager.session_factory)

        for r in resources:
            client = self.get_client(session, self.manager.resource_type)
            ancestors = client.execute_command(
                'getAncestry', {'projectId': r['projectId']}).get('ancestor')
            parents[r['projectId']] = [
                a['resourceId']['id'] for a in ancestors
                if a['resourceId']['type'] == 'folder']
        self.parents = parents
        self.folder_ids = set(itertools.chain(*self.parents.values()))

    def load_folders(self):
        folder_manager = self.manager.get_resource_manager('gcp.folder')
        self.folders = {
            f['name'].split('/', 1)[-1]: f for f in
            folder_manager.get_resources(list(self.folder_ids))}

    def load_metadata(self):
        raise NotImplementedError()

    def diff(self, resources):
        raise NotImplementedError()

    def process(self, resources):
        if self.attr_filter:
            resources = self.filter_resources(resources)

        self.load_hierarchy(resources)
        self.load_metadata()
        op_set = self.diff(resources)
        client = self.manager.get_client()
        for op in op_set:
            self.invoke_api(client, *op)


@Project.action_registry.register('propagate-labels')
class ProjectPropagateLabels(HierarchyAction):
    """Propagate labels from the organization hierarchy to a project.

    folder-labels should resolve to a json data mapping of folder path
    to labels that should be applied to contained projects.

    as a worked example assume the following resource hierarchy

    ::

      - /dev
           /network
              /project-a
           /ml
              /project-b

    Given a folder-labels json with contents like

    .. code-block:: json

      {"dev": {"env": "dev", "owner": "dev"},
       "dev/network": {"owner": "network"},
       "dev/ml": {"owner": "ml"}

    Running the following policy

    .. code-block:: yaml

      policies:
       - name: tag-projects
         resource: gcp.project
         # use a server side filter to only look at projects
         # under the /dev folder the id for the dev folder needs
         # to be manually resolved outside of the policy.
         query:
           - filter: "parent.id:389734459211 parent.type:folder"
         filters:
           - "tag:owner": absent
         actions:
           - type: propagate-labels
             folder-labels:
                url: file://folder-labels.json

    Will result in project-a being tagged with owner: network and env: dev
    and project-b being tagged with owner: ml and env: dev

    """
    schema = type_schema(
        'propagate-labels',
        required=('folder-labels',),
        **{
            'folder-labels': {
                '$ref': '#/definitions/filters_common/value_from'}},
    )

    attr_filter = ('lifecycleState', ('ACTIVE',))
    permissions = ('resourcemanager.folders.get',
                   'resourcemanager.projects.update')
    method_spec = {'op': 'update'}

    def load_metadata(self):
        """Load hierarchy tags"""
        self.resolver = ValuesFrom(self.data['folder-labels'], self.manager)
        self.labels = self.resolver.get_values()
        self.load_folders()
        self.resolve_paths()

    def resolve_paths(self):
        self.folder_paths = {}

        def get_path_segments(fid):
            p = self.folders[fid]['parent']
            if p.startswith('folder'):
                for s in get_path_segments(p.split('/')[-1]):
                    yield s
            yield self.folders[fid]['displayName']

        for fid in self.folder_ids:
            self.folder_paths[fid] = '/'.join(get_path_segments(fid))

    def resolve_labels(self, project_id):
        hlabels = {}
        parents = self.parents[project_id]
        for p in reversed(parents):
            pkeys = [p, self.folder_paths[p], 'folders/%s' % p]
            for pk in pkeys:
                hlabels.update(self.labels.get(pk, {}))

        return hlabels

    def diff(self, resources):
        model = self.manager.resource_type

        for r in resources:
            hlabels = self.resolve_labels(r['projectId'])
            if not hlabels:
                continue

            delta = False
            rlabels = r.get('labels', {})
            for k, v in hlabels.items():
                if k not in rlabels or rlabels[k] != v:
                    delta = True
            if not delta:
                continue

            rlabels = dict(rlabels)
            rlabels.update(hlabels)

            if delta:
                yield ('update', model.get_label_params(r, rlabels))
