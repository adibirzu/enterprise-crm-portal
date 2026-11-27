# CRM source and umbrella integration

CRM owns its source and its cross-service contract. Use the
standalone CRM repository as the canonical source. Select one local checkout
for ongoing work only after checking all candidate checkouts for unique commits
and dirty files. Preserve those changes; checkout consolidation is a separate
operator task.

The umbrella consumes CRM as component C27 through its external-project
registry and sync process. The umbrella registry, `external-projects.yaml`, is
the source of truth for the CRM pin. The umbrella owner reviews and performs
each pin refresh, validates the resulting snapshot, and records an integration
evidence receipt. A CRM commit alone does not update the umbrella.

The CRM-owned [cross-service contract](../docs-site/integrations/cross-service-contract.md)
and `/api/integrations/schema` describe the integration. Browser sessions
protect customer and order data; order creation also accepts the configured
service key. Source order references make retries idempotent, with conflicting
payloads rejected. Public health endpoints report application health. Local
fixture tests do not establish deployed behavior or release acceptance.

The umbrella control plane remains owned by the umbrella repository. Its
operator portal is a separate component and is not the CRM source.
