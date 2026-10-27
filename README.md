# tianquan-jianshen-service

[English](README.md) | [中文](README.zh-CN.md)

Tenant-isolated IAM/RBAC3 management and runtime user authorization for Stellar Enclosure. All first-party modules start at **0.0.1**.

## Current capabilities

- Manage businesses, applications, users/directories, organizations and positions; register versioned permission manifests with source receipts, deployment qualifications and explicit catalog activation.
- Maintain role DAGs, inheritance, user assignments, explicit permission-code grants and user-level active role sets. Evaluate separation-of-duty, prerequisite and cardinality constraints before accepting mutations.
- Decide function, operation, data and field access from immutable authorization snapshots; provide management delegation policies, authorization simulation and role-change impact analysis.
- Persist mutation journals/audit evidence and publish runtime snapshots with fail-closed fences; expose runtime status/retry and the scoped permission-manifest protocol.
- Integrate with Tianshu configuration/service registration and Yuheng definition reporting; enforce user permissions in consuming services through the Starter.

## Modules and boundaries

| Module | Responsibility |
|---|---|
| [Contract](stellar-enclosure-tianquan-jianshen-contract/) | Stable DTOs, manifests, enums and authorization decision contracts. |
| [Core](stellar-enclosure-tianquan-jianshen-core/) | Pure Java role graphs, activation algorithms, permission algebra and constraints. |
| [Starter](stellar-enclosure-tianquan-jianshen-starter/) | Service-side enforcement, Shoubing JWT validation and runtime authorization state consumption. |
| [Gateway adapter](stellar-enclosure-tianquan-jianshen-gateway-adapter/) | Internal Yuheng integration without depending on the Admin implementation. |
| [Admin](stellar-enclosure-tianquan-jianshen-admin/) | Management/runtime decision APIs, PostgreSQL facts, workers, Redis projections and platform integration. |

The code-level responsibility here is user authorization and IAM governance. [Shoubing](https://github.com/Stellar-Enclosure/tianquan-shoubing-service) handles login and token issuance; Jianshen does not issue tokens or own personnel sessions. SERVICE callers are checked against Shoubing scopes rather than borrowing USER role decisions. The [React SDK](https://github.com/Stellar-Enclosure/web-sdk/tree/main/packages/stellar-enclosure-tianquan-jianshen-react-sdk) and [console](https://github.com/Stellar-Enclosure/tianquan-jianshen-web) are separate npm repositories/workspaces, not modules in this Maven reactor.

Management APIs primarily use `/api/tianquan-jianshen/v1`, with bootstrap/about under `/api/v1/auth` and internal runtime decisions under `/internal/v1/authorization`. PostgreSQL/Redis projection health, Tianshu leases, Yuheng release consistency and actual routed requests are separate observations; see the [architecture](docs/architecture.md), [API/manifest contract](docs/api-and-manifest.md) and [security boundaries](docs/security-boundaries.md).

Clean-environment initialization uses the explicit [permission catalog B0 and administrator B1 commands](docs/permission-catalog-bootstrap.md). B0 provisions finite source authority before registration; B1 grants a reviewed list of active permission codes after activation. Neither runs during application startup or ordinary CI.

Tenant authorization policy-version increments use the existing JPA version as an optimistic compare-and-set; a concurrent change can make the transaction fail at flush or commit. A lagging replica may expose older authorization data. Other authorization locking paths still require adaptation before this service can use strict read/write splitting.

## Build

Requires Java 25 and the included Maven Wrapper. The shared parent manages Spring Boot 4.1.2. Once the 0.0.1 dependencies are published:

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

Publishes the Jianshen parent, contract, core and Starter. Admin and the gateway adapter remain internal and are excluded. Requires the published platform parent, Components and Shoubing Starter.

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
