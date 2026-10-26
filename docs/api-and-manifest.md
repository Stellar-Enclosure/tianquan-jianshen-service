# Tianquan-Jianshen API and Resource Manifest Contract

## 1. Common HTTP contract

- Base path: `/api/tianquan-jianshen/v1`.
- IDs are decimal strings on JSON/TypeScript boundaries. Clients must not coerce
  them to JavaScript `number`.
- Success envelope: `{ "data": ..., "meta": { "requestId": "...", "traceId": "...", "timestamp": "..." } }`.
- Error envelope contains stable `code`, safe `message`, `traceId`, `timestamp`
  and optional field violations; it never contains a stack trace or secret.
- Tenant comes from the verified principal. Only xingyuan administration routes
  accept `X-Tianquan-Jianshen-Target-Tenant`, and the caller needs the xingyuan permission.
- Mutation commands use `If-Match`/expected version and `Idempotency-Key` where
  declared. A repeated key with a different request hash is rejected.
- Unknown JSON properties and malformed enum values are rejected.

## 2. Authentication boundary and role activation

Tianquan-Jianshen exposes no login, Refresh, logout, JWKS, authorization-code or personnel
Session endpoint. Browser and API authentication are handled by Tianquan-Shoubing through the
Yuheng. Every Tianquan-Jianshen request receives an Tianquan-Shoubing-signed USER Access Token and Tianquan-Jianshen
locally verifies it with the Tianquan-Shoubing Starter; Tianquan-Jianshen never reads a Refresh Token.

| Method | Path                                            | Semantics                                                      |
|--------|-------------------------------------------------|----------------------------------------------------------------|
| GET    | `/api/v1/auth/bootstrap`                        | Current identity-facing Tianquan-Jianshen bootstrap and activation summary |
| GET    | `/api/tianquan-jianshen/v1/auth/role-activation-candidates` | Assigned canonical roots and explanations                      |
| GET    | `/api/tianquan-jianshen/v1/auth/role-activations`           | Current complete user-level active-root set                    |
| PUT    | `/api/tianquan-jianshen/v1/auth/role-activations`           | Atomically replace the complete user-level active-root set     |

Role activation does not accept a login or Session ID. It accepts multiple role IDs, maps
children to roots, expands whole families, and rejects same-APP mutually
exclusive roots before mutation.

## 3. Tenant and directory

| Method | Path | Semantics |
| --- | --- | --- |
| GET/POST | `/xingyuan/tenants` | List or create tenants from xingyuan context |
| GET | `/xingyuan/tenants/{tenantId}` | Platform tenant detail |
| PUT | `/xingyuan/tenants/{tenantId}/status` | Tenant status transition with version check |
| GET | `/users` | Tenant-filtered user list |
| GET | `/users/{userId}` | Tenant user detail |
| PUT | `/users/{userId}/status` | User status transition with version check |
| GET | `/org-units` | Directory organization-unit view |
| GET | `/positions` | Directory position view |
| POST | `/internal/directory-snapshots` | Trusted provider snapshot submission |
| GET | `/directory-snapshots/{snapshotId}` | Immutable snapshot receipt/detail |

Target-tenant headers are never honored on ordinary tenant business routes.

## 4. Application, Manifest, role and constraints

| Area | Routes |
| --- | --- |
| Historical application/resource reads | `GET /iam/resource-catalog/applications`, `GET /iam/resource-catalog/applications/{id}/resources`, `GET /iam/resource-catalog/applications/{id}/fields`, `GET /iam/resource-catalog/resources/{id}/fields`; legacy resource archive remains an audited historical operation |
| Permission manifests/catalogs | `/api/v1/permission-manifests/**` for scoped machine registration; `/api/v1/permission-catalogs/**` for candidate, Diff, governance and qualified activation |
| Role graph/permission | Existing role/inheritance/impact APIs; explicit permission-code read/replace at `/api/v1/roles/{id}/permissions` with complete target and version |
| Constraints | Existing SOD sets, prerequisite groups, cardinality, scoped Data Rules and Operation-SOD Rules; historical Field Rule reads remain available |

The current [permission catalog contract](permission-catalog-api.md) defines exact paths, six-part targets, producer ownership, source receipts and deployment qualifications. Registration saves an immutable candidate; the complete qualified activation set changes the active pointer with CAS. Absence from an activated producer cannot preserve runtime access through a historical row. The former CI resource registration, resource-permission mapping, resource-role grant and manual FIELD write chains are retired. Definitions and FIELD rules are code-owned; roles grant explicit permission codes. First installation follows the explicit [B0/B1 commands](permission-catalog-bootstrap.md).

### Data Rule catalog scope

Data Rule endpoints remain under `/api/tianquan-jianshen/v1/iam/policies/data-rules`.
They now require the complete catalog identity: `catalogScopeId`, `tenantId`,
`businessCode`, `applicationCode`, `namespaceCode`, and `environment`. Tenant is
an assertion against the authenticated USER; it is never a selectable authority.

- `GET /data-rules` requires all six single-valued query parameters. Missing,
  duplicate or unknown target parameters are rejected. Results contain only that
  tenant/catalog scope/application and each `DataRuleVO` includes its full `target`.
- `POST /data-rules` and `PUT /data-rules/{ruleId}` require `application/json` and
  the body below. `target` is mandatory. The shared strict catalog JSON codec
  rejects duplicate/unknown fields, trailing JSON and numeric IDs.
- `applicationId` must equal the application bound to the target scope. `roleId`
  must have an enabled catalog role binding in that scope and refer to an active
  role in the same tenant/application. `permissionId` now identifies a permission
  in `rbac3_catalog_permission` in that exact scope, with active governance state;
  it is not an ID in the retired global permission source.
- Existing rule updates cannot move catalog scope, application, role or permission.
  `expectedVersion` still performs the existing optimistic version check. The
  Data Rule request `expectedVersion` and response `version` deliberately retain
  their existing JSON integer representation; they differ from the decimal-string
  binding version used by the new API-007 role-permission endpoint.

```json
{
  "target": {
    "catalogScopeId": "100",
    "tenantId": "10",
    "businessCode": "trade",
    "applicationCode": "orders",
    "namespaceCode": "default",
    "environment": "test"
  },
  "applicationId": "20",
  "roleId": "30",
  "permissionId": "40",
  "scopeType": "DEPT_TREE",
  "directorySnapshotVersion": 5,
  "references": [{"referenceType": "DEPT", "referenceId": "50"}],
  "validFrom": "2026-10-25T00:00:00Z",
  "validTo": null,
  "expectedVersion": 0
}
```

The command derives its audit actor from the authenticated USER. Within the
existing SQL transaction it reuses `CatalogAdministrationGuard` to lock the
scope, tenant policy state and bound user in the shared order and reject stale
snapshots. It then checks same-scope role/permission facts before any insert or
reference replacement. Policy-version increment and the existing
`DATA_RULE_CHANGED` Outbox event remain in that transaction. No default scope is
inferred for an old request and no legacy permission lookup is used on this path.

The existing rule kinds, time-window checks and nonnegative optional directory
snapshot version remain unchanged. These source and unit changes do not prove
external directory readiness, PostgreSQL foreign-key/rollback behavior or deployed
Runtime decisions. Eighteen focused tests passed, including real MockMvc/strict
JSON binding and direct repository scope/CAS failure checks; their persistence
collaborators are test doubles. The corresponding RW constraint client/page still
requires the new `target` and scoped GET query integration before the browser flow
can be accepted.

## 5. Assignment and delegated management

Assignments are qualification records, not active roles. Routes under
`/users/{userId}/role-assignments` support list, create, suspend, resume and
revoke. Mutations require version/idempotency evidence and enforce SSD,
prerequisites, cardinality, target scope and privileged/self-assignment rules.

Management Policy routes are `/management-policies`, detail/update/disable,
`/management-capabilities/me`, `/manageable-users` and `/manageable-roles`.
One complete policy must authorize Subject, target Scope, role Root and
Operation. Fragments from multiple policies are never combined.

## 6. Decision, audit and runtime

| Method | Path                                           | Semantics                                           |
|--------|------------------------------------------------|-----------------------------------------------------|
| POST   | `/internal/authorization/decisions`            | Typed Function/Data/Field decision                  |
| GET    | `/internal/v1/authorization/snapshots/current` | Internal immutable user authorization snapshot      |
| POST   | `/internal/authorization/fences/verify`        | Verify mutation Fence state                         |
| POST   | `/internal/business-participations`            | Append idempotent participation fact                |
| GET    | `/internal/business-participations/conflicts`  | Operation-SOD conflict evidence                     |
| GET    | `/audit-logs`                                  | Redacted, signed-cursor audit query                 |
| POST   | `/simulations/authorization`                   | Consistent-snapshot decision simulation             |
| POST   | `/simulations/role-change-impact`              | Role-change impact simulation                       |
| GET    | `/runtime/status`                              | Runtime subsystem status                            |
| GET    | `/runtime/mutations`                           | Bounded mutation journal query                      |
| POST   | `/runtime/mutations/{id}/retry`                | Retry one stable FAILED mutation ID                 |
| GET    | `/runtime/yuheng-tianshu-status`                  | Separate Definition, Lease and Release observations |

Internal routes require service identity plus exact tenant/APP boundaries; they
are not alternate public administration routes.

## 7. Resource Manifest v1

Submission body:

```json
{
  "applicationId": "9007199254740993",
  "definitionSetId": "definition-set-20260730",
  "manifest": {
    "schemaVersion": "tianquan-jianshen-resource-manifest/v1",
    "applicationCode": "orders",
    "applicationName": "Order Management",
    "artifactVersion": "2.4.0",
    "buildId": "git-abcdef12",
    "manifestVersion": 17,
    "generatedAt": "2026-07-30T10:00:00Z",
    "checksum": "sha256:canonical-content",
    "apps": [],
    "menus": [],
    "routes": [],
    "actions": [],
    "apis": [],
    "fieldDefinitions": []
  }
}
```

Resource kinds use stable `code`, optional `parentCode`, display metadata,
route/component information, required permission, and Yuheng operation
identity for APIs. Mechanical identity fields cannot change in place.

Field definitions bind `resourceCode + fieldCode` to a JSON path, data type,
sensitivity, default access, optional masking strategy, write/export flags.
Sensitive fields default to no access. Masking is performed server-side; clients
must not receive a raw value and then hide it visually.

The checksum is calculated from a canonical, stable-key serialization excluding
transport-only metadata. A duplicate `definitionSetId` with different content
or checksum is rejected.

## 8. Yuheng discovery

Every externally or internally routed controller operation has an explicit,
stable `@GatewayOperation` name. Tianquan-Jianshen Admin reports the complete definition set
to Yuheng Admin and separately registers `HTTP_PROVIDER` in Tianshu. Yuheng Engine
routes the explicit Release using Tianshu instances. Definition acknowledgement,
provider lease, Release publication and actual routing are separate acceptance
facts and must be recorded separately.
