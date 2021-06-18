from c7n.filters.core import ValueFilter

from c7n.utils import local_session, type_schema


class IamPolicyFilter(ValueFilter):
    """Filters resources by its associated IAM Policy.

    :example:

    .. code-block :: yaml

       policies:
        - name: gcp-iam-policy
          resource: gcp.kms-cryptokey
          filters:
            - type: iam-policy
              key: "bindings[*].members"
              op: intersect
              value: ["allUsers", "allAuthenticatedUsers"]
    """

    schema = type_schema('iam-policy', rinherit=ValueFilter.schema)
#     permissions = ('compute.instances.getEffectiveFirewalls',)

    def get_client(self, session, model):
        return session.client(
            model.service, model.version, model.component)

    def process(self, resources, event=None):
        model = self.manager.get_model()
        session = local_session(self.manager.session_factory)
        client = self.get_client(session, model)

        for r in resources:
            iam_policy = client.execute_command('getIamPolicy', self._verb_arguments(r))
            r["iamPolicy"] = iam_policy
        return super(IamPolicyFilter, self).process(resources)

    def __call__(self, r):
        return self.match(r['iamPolicy'])

    def _verb_arguments(self, resource, identifier="resource"):
        """
        Returns a dictionary passed when making the `getIamPolicy` and 'setIamPolicy' API calls.

        :param resource: the same as in `get_resource_params`
        """
        return {identifier: resource[self.manager.resource_type.id]}
