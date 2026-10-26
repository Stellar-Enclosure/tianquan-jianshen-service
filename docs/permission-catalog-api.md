# Permission catalog administration API

This is the implemented source contract for the permission catalog UI and the shared registration CLI. PostgreSQL and deployed HTTP acceptance remain separate checks. The catalog uses the verified USER or SERVICE identity; a target in a body/query is an assertion, never an identity selector.

All endpoints use the existing `ResultRecord` envelope (`data` contains the result; success code is `10000`). IDs and versions below are canonical decimal strings. Counts are JSON numbers; times are ISO-8601 Instants. Unknown fields, duplicate query parameters and numeric-to-string ID/version coercion are rejected. Data Rule's existing numeric `expectedVersion`/`version` is deliberately retained; see [Data Rule scope](api-and-manifest.md).

## Target and USER permissions

A target always contains exactly these six fields:

```json
{
  "catalogScopeId": "101",
  "tenantId": "201",
  "businessCode": "xingyuan",
  "applicationCode": "tianquan-jianshen",
  "namespaceCode": "default",
  "environment": "test"
}
```

`applicationCode` is the canonical resource application, not an old `*-admin` system alias. The environment and namespace must match the provisioned deployment; do not substitute `dev` for `test`. The browser first reads the available scopes rather than inventing a scope ID. USER administration is limited to the verified tenant and rechecks current tenant policy, user authorization version and credential/snapshot expiry inside the mutation transaction.

| USER permission | Operations |
| --- | --- |
| `system:permission-catalog:read` | Scope/producer/candidate/definition/history reads and live candidate Diff |
| `system:permission-catalog:activate` | Activate a fully qualified set |
| `system:permission-catalog:manage` | Disable, retire, transfer ownership, and approve authorization expansion/explicit producer clear during USER activation |
| `system:role-permission:read` | Read direct role permission grants |
| `system:role-permission:manage` | Replace direct role permission grants |

The corresponding USER OAuth Scope upper bounds are configured explicitly. Machine `tianquan-jianshen:permission-catalog:*` scopes do not substitute for USER permissions/Scopes.

## Read models for management pages

For endpoints requiring a target, pass the six target fields as six single-valued query parameters. Optional cursors are exclusive; omit them or use `0` for the first page.

| Method and path | Additional query | `data` |
| --- | --- | --- |
| GET `/api/v1/permission-catalogs/scopes` | `afterId`, `limit` (default 50, max 100); **no tenant/subject input** | `{scopes:[{scope,applicationId,producerCount}],nextAfterId}` |
| GET `/api/v1/permission-catalogs/producers` | target | `{target,activeRevision,producers:[{producerId,kind,expectedModules,producerRevision,ownerVersion,activeProducerVersion}]}` |
| GET `/api/v1/permission-catalogs/candidates` | target, `producerId`, `beforeVersion`, `limit` (default 20, max 50) | `{target,producerId,activeRevision,producerRevision,candidates,nextBeforeVersion}` |
| GET `/api/v1/permission-catalogs/diff` | target, `producerId`, `producerVersion` | `{target,producerId,producerVersion,expectedActiveRevision,digests,diff}` |
| GET `/api/v1/permission-catalogs/definitions` | target, `kind=RESOURCE\|PERMISSION`, `afterId`, `limit` (default 50, max 100) | `{target,kind,definitions,nextAfterId}` |
| GET `/api/v1/permission-catalogs/definitions/{kind}/{identityId}` | target | `{identity,activeProducerVersion,activeDefinition}` |
| GET `/api/v1/permission-catalogs/versions` | target, `beforeVersion`, `limit` (default 20, max 50) | `{currentRevision,versions:[ActivationDescriptor]}` |
| GET `/api/v1/permission-catalogs/versions` | target, `operationId`; do not combine with paging | Original immutable `ActivationDescriptor` |

`producerId` is a query value on candidate/Diff requests because valid producer IDs may contain `/`; it is not a URL path segment. An enabled-producer list is complete and bounded at 256. Candidate/definition/history lists return bounded summaries, not an unbounded collection of full manifests.

A candidate contains:

```text
producerVersion, digests{policyDigest,metadataDigest,manifestDigest},
state, failureCode, sourceOperationId, repository, commit, buildId,
artifactVersion, createdAt,
qualification|null = {qualificationId,artifactDigest,deploymentId,expiresAt}
```

The qualification shown is a currently valid proof from an enabled, exactly scoped deployment authority with an allowed source ref. The activation command revalidates it; displaying it does not reserve or extend it. `METADATA_PENDING` with an exhausted current Outbox generation is displayed as `FAILED`, even if the terminal callback could not update the manifest row.

A definition summary is `{id,key,producerId,state,version,type,meaning}`. `state` is governance state. `activeDefinition` is the immutable definition selected by the current activation, or null if absent. Identity existence is not proof that a resource is active. Display rules/permission references as read-only; role grants and governance use their separate commands.

The Diff is recalculated against the **current** active producer version and current role grants. Its shape is `{entries:[{kind,domain,key,reason,authorizationExpansion}],authorizationExpansion,conflicts,absenceCompared}`. It highlights resource target changes, PUBLIC changes, relaxed ALL/ANY/field rules, principal/Scope expansion and new resources using already-granted codes. Carry the returned `expectedActiveRevision` into activation; a changed revision requires reloading/reviewing.

## Explicit role grants

GET `/api/v1/roles/{roleId}/permissions` with the target returns:

```text
{target,roleId,version,catalogVersion,
 permissions:[{permissionCode,validFrom,validTo}]}
```

PUT the same path with:

```json
{
  "target": {"catalogScopeId":"101","tenantId":"201","businessCode":"xingyuan","applicationCode":"tianquan-jianshen","namespaceCode":"default","environment":"test"},
  "permissionCodes": ["system:permission-catalog:read"],
  "expectedVersion": "0",
  "validFrom": null,
  "validTo": null
}
```

This replaces the full direct grant set, including scheduled grants. An empty array explicitly clears it. `resourceIds` is rejected. `validFrom=null` uses database transaction time; `validTo` must be later. `expectedVersion` is this scope/role binding's permission version (initially `0`), not a global role version. The role must belong to the same tenant/application; every requested code must be in the currently active catalog and not disabled/retired.

The result is `{target,roleId,version,policyVersion,permissionCodes,addedCount,removedCount}`. Reload the current permission snapshot after a successful mutation; it advances the tenant policy even when the catalog activation remains unchanged. A new definition/registration/activation never grants this role automatically.

## Governance

POST `/api/v1/permission-catalogs/governance`:

```json
{
  "target": {"catalogScopeId":"101","tenantId":"201","businessCode":"xingyuan","applicationCode":"tianquan-jianshen","namespaceCode":"default","environment":"test"},
  "kind": "RESOURCE",
  "identityId": "301",
  "action": "TRANSFER",
  "expectedVersion": "2",
  "targetProducerId": "next-api"
}
```

`kind` is `RESOURCE` or `PERMISSION`; action is `DISABLE`, `RETIRE`, or `TRANSFER`. Only TRANSFER accepts/requires `targetProducerId`. There is no implicit restore action.

- DISABLE immediately takes precedence over any active definition.
- RETIRE rejects outstanding current catalog references and, for permissions, active/scheduled role grants. Retired identities cannot be redefined, transferred or restored by registration.
- TRANSFER requires an enabled destination producer of the same kind whose configured prefix owns the key/code. It preserves stable ID, key, immutable meaning/type and any existing DISABLED state. Both producer owner versions advance, invalidating old registration plans. It does not move role grants to another scope or alter immutable version rows.

The result is `{target,kind,identity,policyVersion}`. The UI must show impact/Diff and submit the exact current identity version. A conflict requires reloading rather than silently overwriting newer state.

## Qualified activation and unknown outcomes

POST `/api/v1/permission-catalogs/activations` accepts USER or explicitly authorized SERVICE:

```json
{
  "target": {"catalogScopeId":"101","tenantId":"201","businessCode":"xingyuan","applicationCode":"tianquan-jianshen","namespaceCode":"default","environment":"test"},
  "operationId": "00000000-0000-0000-0000-000000000001",
  "expectedActiveRevision": "0",
  "producers": [
    {"producerId":"java-api","producerVersion":"1","qualificationId":"501"},
    {"producerId":"react-web","producerVersion":"2","qualificationId":"502"}
  ]
}
```

The set must include every enabled producer exactly once. Every selected version must be READY with an exact metadata receipt and a still-valid trusted deployment qualification; the selected definitions/messages must form a reference closure. A version may be reused, including for rollback, but rollback creates a **new** activation number and rechecks current governance and grants. The browser only selects existing proof IDs; it cannot mint readiness or artifact proofs.

`ActivationDescriptor` is `{scope,activationVersion,operationId,policyVersion,createdAt,producers}` where each member contains `{producerId,producerVersion,sourceVersion,digests,qualificationId,artifactDigest}`. The descriptor policy version is the version at activation time. Later role/governance changes can increase the tenant policy without changing this immutable descriptor or catalog version.

Keep the same operation ID and exact request when an outcome is unknown. Query `/versions?operationId=...` before retrying. An identical committed operation returns its original descriptor; reusing the operation ID with different content fails. A conflict or expired proof before commit leaves the old active pointer unchanged.

The machine-only qualification endpoint is POST `/internal/v1/permission-catalogs/deployment-qualifications`. It requires the exact `QUALIFY_DEPLOYMENT` SQL grant plus the corresponding signed SERVICE Scope, source-ref allowlist and matching candidate build/commit/digests. Its bounded pre-activation readiness must be current. Arbitrary headers, browser permissions or a candidate's stored metadata cannot provide this proof.

SERVICE history/operation lookup additionally requires `producerId` and `READ_DESCRIPTOR`; the original source registration/lookup remains at `/api/v1/permission-manifests/*`. Tianshu uses GET `/internal/v1/permission-catalogs/{catalogScopeId}/activations/{version}` with the full target and producerId. These internal endpoints are not browser routes.

## Validation boundary

Targeted unit/MVC/Security/HTTP-fixture tests validate the source contracts; they do not demonstrate database commits, real Outbox delivery or deployment readiness. The explicit `tianquan-jianshen-permission-catalog-it` profile contains actual PostgreSQL/Hibernate repository tests and never starts PostgreSQL or a server. It requires an existing approved database URL, username and password-file path and creates/drops only its own random schema. No existing Flyway migration is changed.
