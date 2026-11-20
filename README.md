# tianquan-jianshen-service

[English](README.md) | [中文](README.zh-CN.md)

Tenant-isolated IAM/RBAC3 management and runtime user authorization for Stellar Enclosure. All first-party modules start at **0.0.1**.

## Current capabilities

- Manage businesses, applications, users/directories, organizations and positions; register versioned permission manifests with source receipts, deployment qualifications and explicit catalog activation.
- Maintain role DAGs, inheritance, user assignments, explicit permission-code grants and user-level active role sets. Evaluate separation-of-duty, prerequisite and cardinality constraints before accepting mutations.
- Decide function, operation, data and field access from immutable authorization snapshots; provide management delegation policies, authorization simulation and role-change impact analysis.
- Persist mutation journals/audit evidence and publish runtime snapshots with fail-closed fences; expose runtime status/retry and the scoped permission-manifest protocol.
- Consume Tianshu configuration and report logical API definitions to Yuheng. Enforce user permissions at each resource service through the Starter.

## Modules and boundaries

| Module | Responsibility |
|---|---|
| [Contract](stellar-enclosure-tianquan-jianshen-contract/) | Stable DTOs, manifests, enums and authorization decision contracts. |
| [Core](stellar-enclosure-tianquan-jianshen-core/) | Pure Java role graphs, activation algorithms, permission algebra and constraints. |
| [Starter](stellar-enclosure-tianquan-jianshen-starter/) | Service-side enforcement, Shoubing JWT validation and runtime authorization state consumption. |
| [Admin](stellar-enclosure-tianquan-jianshen-admin/) | Management/runtime decision APIs, PostgreSQL facts, workers, Redis projections and platform integration. |

The code-level responsibility here is user authorization and IAM governance. [Shoubing](https://github.com/Stellar-Enclosure/tianquan-shoubing-service) handles login and token issuance; Jianshen does not issue tokens or own personnel sessions. SERVICE callers are checked against Shoubing scopes rather than borrowing USER role decisions. The [React SDK](https://github.com/Stellar-Enclosure/web-sdk/tree/main/packages/stellar-enclosure-tianquan-jianshen-react-sdk) and [console](https://github.com/Stellar-Enclosure/tianquan-jianshen-web) are separate npm repositories/workspaces, not modules in this Maven reactor.

Management APIs primarily use `/api/tianquan-jianshen/v1`, with bootstrap/about under `/api/v1/auth` and internal runtime decisions under `/internal/v1/authorization`. PostgreSQL and Redis projection health, Tianshu configuration receipts, Kubernetes Service endpoints, Yuheng URL exposure and routed requests are separate observations. See the [architecture](docs/architecture.md), [API/manifest contract](docs/api-and-manifest.md) and [security boundaries](docs/security-boundaries.md).

The default-off execution-grant authorization service can independently resolve a sealed intent through Shoubing, match its attested source tuple to the verified calling SERVICE, and read the current USER roles and activated resource policy in one local transaction. Deployments must explicitly configure finite `egon.tianquan-jianshen.execution-grants.policies` containing each system/purpose, exact normal and optional session API keys and paths, minimum permission codes, and permission-to-USER-scope mappings; the existing identity authority binding for the issuer and source resource must include `tianquan-shoubing:execution-grant:resolve`. Missing bindings or policy drift fail closed. Shoubing identity checks and the local authorization transaction are separate points in time; callers must recheck before each protected execution boundary, and a concurrent revocation is not globally atomic with a subsequent model call. The default-off internal POST `/internal/v1/authorization/execution-grants:decide` requires the separately scoped SERVICE credential `service:authorization:execution`; it does not grant permissions or register an application.

For example, a reviewed deployment policy for the Tianji start endpoints has this shape (the separate identity-authority bindings, registrations, permissions and grants must already exist):

```yaml
egon:
  tianquan-jianshen:
    execution-grants:
      enabled: true
      policies:
        - system-code: tianji
          purpose: TIANJI_AGENT_RUN_EXECUTION
          resource-key: tianji.api.agent.start
          resource-path: /api/tianji/v1/agent-runs
          session-resource-key: tianji.api.agent.startSession
          session-resource-path: /api/tianji/v1/agent-runs/with-session
          required-permissions: [TIANJI_AGENT_START]
          session-permissions: [TIANJI_AGENT_READ]
          permission-scopes:
            TIANJI_AGENT_START: ["tianji:agent:start"]
            TIANJI_AGENT_READ: ["tianji:agent:read"]
```

`HttpExecutionAuthorizationClient` is an explicit per-issuer, per-tenant SERVICE client for this endpoint. It compares the returned issuer, tenant, subject, resource, purpose, run identifier, input fingerprint, session flag and deadline with the caller's local expectation before returning a decision. It bounds the request and response and applies one total deadline to SERVICE token acquisition and the decision exchange, follows no redirects, and does not replay requests. Bounded token operations share the Shoubing client’s finite no-queue pool; an operation that ignores interruption occupies a slot until it returns. The executing Jianshen build must also have its own matching permission manifest activated before the compiled SERVICE policy guard will accept the endpoint.

The separate POST `/internal/v1/authorization/execution-grants:decide-scopes` and `HttpExecutionAuthorizationClient.decideScopes` project current data scopes for a reviewed deferred intent. It requires its own `service:authorization:execution-scopes` SERVICE credential, the matching active resource policy, enabled execution grants and `scoped-decisions: true` on the exact configured system/purpose policy. The default is false, including the compatible older Policy constructor. It shares owner-ticket resolution, current role/resource checks and bounded request handling with the original decision; that original response still has its thirteen fields. A Memory consumer can issue an independent Memory-read purpose and bind its own run/owner/scope fingerprint before using this projection; an ordinary execution decision does not confer Memory or team access.

`ExecutionScopeAuthorizationContract.Decision` wraps the original execution decision, the separate internal `rbac3UserId`, snapshot generation time and only the configured required permissions' `DataScopeDecision` values. Data-scope subject IDs are RBAC user IDs and must not be compared directly to the external identity subject. Tenant, internal user, permission key, authorization/policy versions and decision timestamp are checked together. The new SDK path has closed root/nested shapes, strict scalar/boolean/ID-array validation and the existing total timeout/64 KiB response bound; its optional null self-user field does not relax the original decoder. Scope projection is evidence from the current authority, not an instruction to infer descendants or create business team memberships. Callers must apply the exact authorized scope and revalidate at their next protected boundary. Source tests use controlled owner/SQL views and the actual identity/compiled-policy guard; deployed directory/IAM behavior remains a separate acceptance step. No permission registration, activation or grants are performed here.

Deferred SERVICE executions use the separate, default-off `egon.tianquan-jianshen.service-execution-grants` policies. Each policy fixes an issuer, tenant, system and purpose, an allowlist of SERVICE source tuples, normal and optional Session API keys and paths, and required scopes; the Shoubing authority binding needs `tianquan-shoubing:service-execution-grant:resolve`. The internal POST `/internal/v1/authorization/service-execution-grants:decide` requires `service:authorization:service-execution`, rechecks the owner-sealed identity and current activated SERVICE resource policy, and does not create a USER or borrow USER roles. `HttpExecutionAuthorizationClient.decideService` additionally compares the returned SERVICE tuple and all run fields against the caller's local `ServiceExpectation`. These settings do not activate or grant permissions, and callers must still recheck at each protected execution boundary.

Clean-environment initialization uses the explicit [permission catalog B0 and administrator B1 commands](docs/permission-catalog-bootstrap.md). B0 provisions finite source authority before registration; B1 grants a reviewed list of active permission codes after activation. Neither runs during application startup or ordinary CI.

Tenant authorization policy-version increments use the existing JPA version as an optimistic compare-and-set; a concurrent change can make the transaction fail at flush or commit. A lagging replica may expose older authorization data. Other authorization locking paths still require adaptation before this service can use strict read/write splitting.

## Build

Requires Java 25 and the included Maven Wrapper. The shared parent manages Spring Boot 4.1.2. This repository explicitly selects the existing Outbox `0.0.2-SNAPSHOT` API used by its source-shard and migration adapters; build it in the source cohort or publish it before a standalone build. Other platform contracts remain `0.0.1`. Once those dependencies are available:

```bash
./mvnw -B -ntp test-compile
```

Before the first Central publication, clone the eight Java repositories next to one another and bootstrap their artifact graph explicitly:

```bash
bash ../Stellar-Enclosure-Parent/scripts/bootstrap-workspace.sh \
  --workspace "$(cd .. && pwd)" \
  --local-repository "$HOME/.m2/repository"

# Resolve subsequent Maven commands and generator subprocesses from this same cache.
export MAVEN_ARGS="${MAVEN_ARGS:-} -Dmaven.repo.local=$HOME/.m2/repository"
```

The bootstrap installs parent/BOM models before building components and business starters in Maven reactor order. It compiles test sources and installs packages with runtime tests disabled. It never runs applications, databases, containers, browsers, or deploy.

## Publish to Maven Central

Publishes the Jianshen parent, contract, core and Starter. The executable Admin is delivered internally. Requires the published platform parent, Components and Shoubing Starter.

Run these commands from this repository. Configure a Central Portal token under Maven server ID `central` and a local GPG signing key; credentials stay outside Git. See the [credential setup and initial dependency order](https://github.com/Stellar-Enclosure/Stellar-Enclosure-Parent/blob/main/docs/first-release.md).

```bash
# Verify release artifacts locally; signing and upload are disabled.
./mvnw -B -ntp -Prelease -Dgpg.skip=true -DskipITs -Dinvoker.skip=true -Darchetype.test.skip=true clean verify

# Sign and publish this repository's public artifacts.
./mvnw -B -ntp -Prelease -DskipITs -Dinvoker.skip=true -Darchetype.test.skip=true clean deploy
```

Unit tests remain enabled. `release` attaches sources, Javadoc and GPG signatures, then publishes through the Central Portal. Ordinary builds and Git pushes do not publish. Each published GAV is immutable: use a new version for changed content, and use `-pl` to select only unpublished modules after a partial release. Before the first release, use the Build section's local bootstrap or publish the prerequisite artifacts first; bootstrap installation alone does not publish dependencies.

## Compatibility and publication

Java packages/classes, Bean names, configuration keys, OAuth/RPC identities, APIs, and database ownership are retained. Existing SQL and DDL history are copied byte for byte. Artifact/build versions and necessary build paths change. A successful build does not imply application startup or live infrastructure acceptance.

Git pushes run validation only. Central and npm publication are separate user actions. CI defaults to initial source bootstrap; after publication set `STELLAR_USE_SOURCE_BOOTSTRAP=false` to consume published artifacts directly. Private organizations may supply the Actions secret `STELLAR_ENCLOSURE_READ_TOKEN` with repository read access.

Original MIT/LGPL licenses and author attribution are preserved.

### Permission manifest delivery

The `permission-producer` profile exports and verifies each final executable independently. See [permission build and controlled delivery](docs/permission-ci.md) for the exact toolchain pin, offline CI, candidate registration and deployment-qualified activation gates. Runtime startup and administrator grants are not CI side effects.

## Authorization snapshot loader compatibility

New integrations use `AuthorizationSnapshotLoader`: every authorization boundary fetches the current account snapshot from the SQL authority and requires the original verified USER token. Requests from different devices share the account's selected role set; no per-device role cache or failure grace is introduced.

`SingleFlightSnapshotLoader` is a deprecated compatibility adapter. Its two constructors, dependent public constructors, and the `singleFlightSnapshotLoader` Spring Bean name remain available. The default Bean is also named `authorizationSnapshotLoader`, and either loader type resolves to the same instance. A custom `AuthorizationSnapshotLoader` (including the old subtype) replaces the default.
