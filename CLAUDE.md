<!-- BEGIN oci-demo-portability-handoff (managed by OCI-DEMO scripts/sync_agent_handoff_pointers.py) -->
> **OCI-DEMO linked project (`EnterpriseCrmPortal`).** Before changing code,
> manifests, stacks, or `.env` templates here, read the standing handoff
> `OCI-DEMO/docs/product/tasks/PRD-016-PORTABILITY-HANDOFF.md` (default checkout:
> a sibling `OCI-DEMO` clone). Rules: no embedded tenant values (OCIDs, IPs, regions,
> compartments); secrets only in local env or OCI Vault; standalone ORM
> stacks accept `parent_compartment_ocid`; report new or renamed env vars
> consumed by OCI-DEMO in `OCI-DEMO/docs/product/tasks/AGENT-HANDOFF.md`.
<!-- END oci-demo-portability-handoff -->

## Modular API contracts

- This is OCI-DEMO component C27. Read the component handoff before changing
  API, configuration, or deployment material.
- Use the public [OCI API Contract Framework](https://github.com/adibirzu/oci-api-contract-framework)
  as design and validation guidance; it is not this product's runtime,
  identity provider, release authority, or provider evidence.
- The CRM product owns its contract, implementation, versioning and consumer
  compatibility. Its current cross-service contract is
  [`docs-site/integrations/cross-service-contract.md`](docs-site/integrations/cross-service-contract.md)
  and its served schema is `/api/integrations/schema`; keep them aligned.
- Keep tenant context and credentials outside contracts: resolve tenant scope
  through product-owned authentication/authorization and configuration, never
  through client-supplied tenancy identifiers. Preserve idempotency and
  compatibility for existing consumers; document and stage any breaking
  change with an explicit migration and rollback path.
- Treat framework checks and local contract validation as code-backed/local
  evidence only. Deployment, identity, OCI configuration, and release
  acceptance require their own product and OCI-DEMO evidence.

<!-- BEGIN shared-harness-routing -->
## Agent context routing
- Global defaults come from the host. Do not re-import or reread global aliases here.
- Read `.agent-context/project-map.md` only to locate task-specific docs, state, skills, or plugins.
- Preserve full technical detail in agent evidence and handoffs; keep human updates brief.
- Any commit/push/deploy step below is procedural, not standing authorization.
- Compatibility references also retain project safety/contracts: consult matching sections before affected actions, regardless of harness.
- CLAUDE compatibility: before using its project-specific workflow, read the relevant sections of `.agent-context/claude-specific.md`; preserve its safety and verification requirements.
<!-- END shared-harness-routing -->
