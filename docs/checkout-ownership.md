# CRM source and umbrella integration

CRM owns its source and its cross-service contract. The published CRM main
revision verified for CRM-GH-2 is `90da4e31dbb2eeba8fd1c8d51c8f8df48b927561`.
Use the standalone CRM repository as the canonical source; select one local
checkout for ongoing work only after checking all candidate checkouts for
unique commits and dirty files. Preserve those changes and do not delete a
checkout as part of this handoff.

The umbrella consumes CRM as component C27 through its external-project
registry and sync process. Its registry currently pins
`65d5cdcb449f38d7e31d6ed825942c3d5b273c77`, an older snapshot; it has not
been updated by this CRM-only change. The umbrella owner must review and
update that pin separately, validate the resulting snapshot and record the
integration evidence. A CRM commit alone does not update the umbrella.

The CRM-owned [cross-service contract](../docs-site/integrations/cross-service-contract.md)
and `/api/integrations/schema` describe the integration. Browser sessions
protect customer and order data; order creation also accepts the configured
service key. Source order references make retries idempotent, with conflicting
payloads rejected. Public health endpoints report application health. Local
fixture tests do not establish deployed behavior or release acceptance.

The umbrella control plane remains owned by the umbrella repository. Its
operator portal is a separate component and is not the CRM source.
