# Permission Runtime host contract

The Runtime and field executor require one trusted deployment configuration plus the complete compiler manifest. Missing configuration closes the protected path. There is no Redis authorization snapshot, expiry extension, or initial-permission fallback.

## Build and instance binding

Package the FULL Java manifest at `META-INF/permissions/manifest-v1.json` in the executing application artifact. Aggregate all expected successful module fragments before the final application packaging step. Compute the final artifact digest only after that step. The artifact digest is supplied by the deployment control plane; it is not embedded into its own artifact and is not accepted from request headers.

The resource-server Starter requires:

- `egon.cola.platform.tianquan.jianshen.runtime.artifact-digest`: trusted final SHA-256 artifact digest.
- `egon.cola.platform.tianquan.jianshen.runtime.catalog-scopes`: finite list of complete `catalog-scope-id`, `tenant-id`, `business-code`, `application-code`, `namespace-code`, and `environment` tuples supported by this deployment.
- The existing `system-code`, authorization endpoint, and SERVICE client binding for the target RBAC authority.

The local registry recalculates policy/manifest digests from the packaged manifest. Each USER and SERVICE execution compares its trusted Runtime response with these digests, the producer identity, the instance artifact digest, full catalog scope and active resource key. An old or absent build cannot use a current permission set.

## Authority bindings

The RBAC owner requires `egon.tianquan-jianshen.catalog-runtime.bindings`, a finite list with:

- `scope`: the full six-field CatalogScope.
- `expected-resource`: the original USER token audience expected at the calling service.
- `service-issuer`, `service-client-id`, `service-app-id`, `source-business-code`, `source-application-code`, `source-environment`, and `receiver-resource`: the exact verified SERVICE tuple allowed to obtain the view.
- `producer-id`, `producer-version`, `artifact-digest`, `policy-digest`, and `manifest-digest`: trusted deployment facts matched to the active descriptor and its SQL qualification.
- `local: true` only for the owner's own resource entry. The local adapter reads SQL directly and does not recursively invoke the HTTP Runtime.

`snapshot-ttl` defaults to 30 seconds and is bounded to 1 second through 5 minutes. Responses never outlive the original USER token. The selected USER issuer must exactly equal the configured tenant SERVICE issuer. No request body or query supplies a subject, issuer, tenant, or catalog scope.

The outgoing identity-authority configuration must contain an explicit SERVICE binding for each `expected-resource` used to validate an original USER token. Those bindings are in addition to the RBAC owner's own audit delivery binding. The IdP Starter validates the original JWT and database security state before Runtime reads.

## Endpoints and consistency

`GET /api/v1/authorization/effective-permissions` returns the frozen API-008 view for the current USER and local binding. It rejects query parameters. `GET /internal/v1/authorization/snapshots/current?systemCode=...` requires `service:authorization:snapshot` and the original USER token in `X-Egon-Subject-Token`; systemCode must match the trusted service binding. Internal decision/fence operations use the same proof and scope selection.

SQL reads lock catalog scope, tenant policy, then user state. They derive current role eligibility, exact-scope character grants and data rules, validate the active producer/deployment facts, and publish an immutable snapshot plus its head in one transaction. Every API authorization boundary consults the SQL owner. The response serializer and input binder use the same compiled policy. A successful field-input check records its scope/version/role/permission/build/resource state in the current request or bounded adapter context. A later method-boundary refresh may shorten expiry, but any authority-state change rejects the request with `FIELD_AUTHORIZATION_VIEW_CHANGED` before business writes. This prevents combining a prior field decision with a later API decision; it does not promise an atomic transaction across separate services. Explicit nulls, aliases, nested input and arrays are checked before business writes; unknown and read-only properties are rejected. A write grant does not grant plain read.

The explicit export/RPC adapters are `PermissionExecutionGuard`, `PermissionFieldBindingGuard`, and `PermissionOutputProjection`. Business adapters must perform every field check before executing a batch write and emit only the authorized output projection. Scanning an entry does not by itself prove that such an adapter has been connected.

A final `AuthorizationService.verifyFence` compares a fresh SQL view with the earlier scope, versions, active-role context and deployment binding. On this owner's database, invoking it inside the business transaction retains the SQL locks until commit. A remote service only obtains consistency at the documented check point; this is not an atomic transaction across separate databases.

Catalog/role events enqueue `rbac3_catalog_rebuild_task` work. Claims use SQL version CAS, owner/token/generation, renewal and deadlines. Snapshot publication rechecks the claim within its transaction. Expired workers cannot publish or complete another claim. Catalog event aggregateVersion is a policy event version; the catalog version is read from the explicit payload and current scope authority.

## Database and Outbox startup

`rbac-sharding-native.yml` lists explicit business and managed Outbox tables on one physical `rbac_primary`. Startup migrates existing RBAC Flyway history on that physical primary, runs the Components managed Outbox initializer, then creates the shared logical datasource. JPA and MyBatis Outbox must use that same datasource instance and local `JpaTransactionManager`; an explicit startup guard checks this binding.

The retired authorization Redis implementations, their host configuration and the Starter Redis dependency are removed. The isolated provisioning fixture uses PostgreSQL for authorization projection; its independent DDC service-registry Redis ownership guard remains for that business dependency. The retired Outbox Flyway helper has no host bean. Historical SQL files are unchanged. Managed Outbox uses its existing `db/egon-outbox-mp/manifest.json` and `egon_outbox.ddl_history`; no second RBAC migration is introduced. SQL projection readiness replaces authorization Redis readiness.

## Validation boundary

This handoff describes source/configuration contracts. No service, database, container, or browser was started during implementation. Real PostgreSQL transaction/claim/migration checks remain a separate external-environment acceptance step. The PostgreSQL-only Maven profile is `tianquan-jianshen-permission-catalog-it`; it must use an explicitly supplied disposable database schema and must never auto-start infrastructure.

## SERVICE policy and finite control-plane bootstrap

`GET /internal/v1/authorization/policies/current?systemCode=...` requires `service:authorization:policy`. It returns only CatalogScope, catalog/policy versions, RuntimePolicyBinding, active resource keys and expiry. The executing host uses its own fixed SERVICE credential. It contains no user, role or permission-code collection. SERVICE API and FIELD execution checks this current SQL policy and local build. FIELD requires explicit SERVICE classification and scopes; protected read/write operations must each exist in fieldPolicy. PUBLIC exempts the character expression only. Input still requires a real writable binder and a mutation API/Command scope. A read API cannot be reused as a write adapter.

HTTP input/output uses Spring's selected HandlerMethod as the trusted API boundary. Non-HTTP adapters use `try (var boundary = permissionExecutionGuard.open(apiResourceKey)) { ... }`; the scope is restored in `close()`, and is not inherited by worker threads. `PermissionOutputProjection` manages this scope internally. SERVICE DTOs with incompatible read/write/admin scopes must use separate explicit input/output/operation projections while retaining the desired JSON shape.

`runtime.bootstrap-service-resource-keys` is a deployment-owned subset of a fixed managed allow-list. Every configured key must exist in the packaged manifest and declare SERVICE scopes. It exempts only active-self-build lookup for the SERVICE branch; the verified Scope and owning SQL Grant remain mandatory. It never exempts USER permission expressions, business methods or field writes. No request header can select this behavior.

RBAC host keys are `tianquan-jianshen.api.manifest.plan`, `.manifest.register`, `.manifest.status`, `.catalog.qualify`, `.catalog.activate`, `.catalog.descriptor`, `.catalog.versions`, `.runtime.userSnapshot`, `.runtime.servicePolicy` (each abbreviated entry has the same `tianquan-jianshen.api` prefix). Tianshu host keys are `tianshu.api.i18nSourceImport.importSource` and `tianshu.api.i18nSourceImport.receipt`. Native control-plane envelopes and Manifest payloads retain their strict protocol schema; they are not treated as business mutation DTOs by the field binder.

## USER OAuth scope upper bound

The existing `egon.cola.platform.tianquan.jianshen.user-scope-policy` remains effective when enabled. For each protected USER expression, a character participates only when the user has that character and satisfies its configured Scope set. ALL/ANY is evaluated on those qualified characters; an ANY group does not require the Scopes of every alternative. For USER-only resources, explicit `oauthScopes` is an additional AND bound. On explicitly mixed USER/SERVICE resources, that list is the SERVICE requirement; USER expressions require the enabled permission-to-Scope map and an explicit mapping for each qualifying character. A USER-only character with neither a configured mapping nor an explicit resource Scope declaration cannot satisfy the protected expression while this policy is enabled. The same qualification applies independently to protected field plainRead/maskedRead/write expressions. SERVICE evaluation never uses the USER map.

## Transport-only JSON configuration

The Starter exposes `PermissionJsonMapperFactory`, not a Jackson `Module` bean. Hosts must call `factory.forTransport(sharedMapper)` for their HTTP JSON converters. The returned mapper is a copy. Do not register `Rbac3FieldJacksonModule` on the shared storage/RPC/notifier mapper, and do not mutate that shared mapper from a converter customizer. The factory preserves the existing codec options while adding actual-input and output-field enforcement only to the transport copy. The explicit `PermissionOutputProjection` bean also uses this isolated mapper.

## Host-local API-008 wrappers

Each resource host declares its own `GET /api/v1/authorization/effective-permissions` USER endpoint in its producer manifest. It calls the shared `CurrentEffectivePermissionView.current(request, HOST_RESOURCE_KEY)` using a code constant for that host's resource key. The component rejects all query parameters, SERVICE/anonymous identities, missing verified USER token carrier, absent/expired views and mismatched local deployment bindings. It returns only the current request's already validated SQL view and does not make another authority request or exchange tokens.

The Runtime applicationCode is canonical: `tianquan-jianshen`, `tianquan-shoubing`, `tianshu`, `yaoguang`, or `yuheng` as appropriate. The RBAC owner's system-code is `tianquan-jianshen`; legacy `*-admin` aliases do not invent additional catalog scopes. B0 must establish the explicit canonical application and full scope.

## Reviewed native anonymous boundary

`runtime.anonymous-resource-keys` defaults to empty. Its only currently reviewed entry is `tianshu.api.adminUiI18n.publicBundle`. The executor additionally requires the exact existing GET `/api/v1/tianshu/i18n/public/bundle`, the host's IdP endpoint policy classifying that path PUBLIC, and a compiled PUBLIC declaration. Only a single `locale` parameter is accepted. The special output projection permits only the five explicitly READ_ONLY/PUBLIC properties of `DdcPublicI18nBundleResult`, which contains packaged login text only. It grants no input capability, tenant catalog lookup or USER permission view. No `auth/bootstrap` naming convention, prefix or generic PUBLIC classification expands this boundary; API-008 remains USER-only.


## Bounded FIELD catalog projection

Every host declares `GET /api/v1/authorization/field-catalog` as PUBLIC metadata for the current verified USER. PUBLIC does not allow an anonymous or SERVICE caller. The only query parameter is a repeated `keys`; a request contains 1 through 256 unique stable FIELD keys. It cannot select subject, tenant, issuer or scope. Responses use `Cache-Control: no-store` and the existing ResultRecord envelope:

```json
{"data":{"catalogScope":{},"catalogVersion":"1","fields":{"host.field.key":{"access":"PROTECTED","fieldPolicy":{"valueType":"STRING","plainRead":{},"maskedRead":null,"write":{},"masker":null},"inputBinding":true}}}}
```

The snippet shows the shape only; CatalogScope and requirement values retain their full existing contracts. `fieldPolicy` is the existing `PermissionManifest.FieldPolicy`, with `valueType`, `plainRead`, `maskedRead`, `write`, and `masker`. It can be null for PUBLIC metadata. `inputBinding` is always a boolean and is independent of the write requirement. A host supplies actual input DTO types and its actual HTTP transport mapper to `PermissionFieldCatalog.current(request, hostResourceKey, transportMapper, actualInputDtoTypes)`. A property is bindable only if its DTO is in that input set, the mapper can deserialize that property, and no effective member marks it READ_ONLY. Output DTOs, undeclared inputs and read-only fields report false. Metadata does not grant any permission.

The shared `currentForHttp(request, hostResourceKey, converters, handlers, ownedModelPackagePrefixes, explicitInputs)` helper derives a bounded DTO set from registered `@RequestBody`, `@RequestPart`, and `@ModelAttribute` handler parameters. It selects the actual first JSON reader and its type-specific ObjectMapper, then retains that mapper while following writable nested DTO properties. A later generic converter cannot replace an earlier strict reader. The R wrapper uses this helper; other hosts also supply their reviewed package prefixes and explicit manual/query/multipart adapter root DTOs. The helper depends only on existing Spring Web converter and HandlerMethod types, without adding an MVC dependency to non-MVC Starter consumers. Every requested FIELD must exist in the local compiler manifest and be active under the same current scope/build as API-008. The frontend must compare catalogScope/catalogVersion before using the projection and must never infer inputBinding from PUBLIC or a write rule.

## Qualification time and identity authority configuration

An active deployment must reference qualification whose `verifiedAt <= activation.createdAt < expiresAt`, with matching producer/artifact/policy/manifest facts. That qualification window governs new activation and rollback; its later expiry does not invalidate an already activated catalog. Current USER/SERVICE credentials and permission-view expiry are always checked against current time.

The R base profile declares finite tenant-A, tenant-B and platform trusted issuers plus matching outgoing identity-authority bindings. Deployment must supply those issuer/JWKS/realm/trust-version values, authority URL/audience, host resource URI and the exact identity SERVICE registration IDs. Local profiles inherit this finite table. Removed audit-spool/Redis-revocation settings cannot supply missing SQL authority. No credentials are embedded in these examples or in repository defaults.
