# Tianquan-Jianshen Architecture, Algorithms, and Design Patterns

## 1. Architectural view

Tianquan-Jianshen separates control-plane writes from runtime enforcement:

```text
Admin HTTP/API
  -> application facades and domain services
  -> PostgreSQL facts + mutation journal + outbox
  -> projection workers
  -> immutable Redis authorization snapshots
  -> resource-service Starter policy enforcement
```

The Contract module owns wire compatibility. Core owns deterministic policy and
graph algorithms. Admin owns I/O and orchestration. The resource-service Starter
validates the bearer and consumes the scoped authorization decision through the
published runtime contract.

The integration control plane is deliberately decomposed:

```text
Definition report receipt  -- Yuheng accepted the logical interface definition
Tianshu configuration receipt  -- the identified workload applied the expected revision
Kubernetes Service and EndpointSlice  -- the cluster observed backend endpoints
Yuheng URL exposure status  -- the declared HTTPRoute and current observation agree
Routed request  -- the request reached the resource and its authorization was evaluated
```

No single health flag substitutes for these observations.

### 1.1 Configuration and workload discovery

Tianshu delivers configuration by `bizCode + appCode + env + resourceName`.
The deployment selects the namespace binding. The application starts from its
immutable ConfigMap and uses its SERVICE bearer and projected workload token
for protected snapshots and receipts. Readiness reflects the effective
configuration revision and application health.

Kubernetes owns the Service, endpoint state and workload observation. Cilium
Gateway uses explicitly approved HTTPRoute bindings to the Service. The
resource-service Starter makes the authorization decision when the request
reaches the service.

### 1.2 Atomic runtime policy and document catalog

The exact Tianshu applier adapts the Tianquan-Jianshen policy leaf into one immutable policy
snapshot. Each apply is serialized, builds and validates a complete candidate,
then atomically swaps the reference. Readers take one snapshot per command, so
they cannot observe mixed fields. A runtime publication replaces the complete
YAML resource; if any consumer rejects it, Tianshu rolls back the property source and
already-applied leaves.

The current Tianquan-Jianshen policy is `tianquan-jianshen.maximum-active-roots` plus its fixed range.
An invalid candidate records only key, target version and bounded error code.
The active snapshot and Tianshu repository version/checksum remain at the
last-known-good state. A later higher valid version recovers the key. Tianquan-Jianshen does
not issue tokens or own personnel sessions; the value governs new role-activation
commands only and never rewrites committed activation facts.

Spring MVC remains the mechanical source for HTTP method, path, media types and
parameters. Existing Yuheng annotations add business grouping, stable operation
name, summary, tags, accessibility and schema descriptions. The resulting
Yuheng Interface Catalog is the sole API document center. Tianquan-Jianshen reports a
Definition but never auto-publishes a Yuheng Release.

Record the configuration receipt, accepted Definition, Kubernetes endpoint state,
current URL exposure and routed-request result independently. The routed-request
result includes the response status and the selected resource handler.

## 2. Role graph model

Roles form a tenant- and APP-scoped directed acyclic graph (DAG). An edge points
from senior role to junior role. A role may have multiple parents only when all
paths resolve to one canonical root; multiple distinct roots are ambiguous and
are rejected for activation.

### 2.1 Graph validation

For a proposed graph mutation:

1. Lock the affected APP graph using the PostgreSQL adapter.
2. Apply the proposed edge to an in-memory candidate graph.
3. Run a color-marked depth-first traversal to reject back edges (cycles).
4. Track path depth and reject paths beyond the configured hard limit.
5. Rebuild closure rows atomically from the validated graph.
6. Increment the role/policy version and append the mutation journal record.

For `V` roles and `E` inheritance edges, cycle/depth validation is `O(V + E)`
with `O(V)` working memory. Closure rebuild materializes reachability for reads;
the implementation sets hard graph limits so a tenant cannot turn validation
into an unbounded traversal.

### 2.2 Canonical root and family expansion

Activation accepts role IDs but authorizes root families:

1. Traverse parent edges from each selected role and collect roots.
2. Require exactly one root for each selected role.
3. Deduplicate roots using stable IDs.
4. Traverse descendant edges from every root, including the root itself.
5. Sort roots and family members by stable ID before checksum generation.

The traversal is `O(Vr + Er)` for the reachable subgraph. Seeded metamorphic
tests permute input and edge order to prove that roots, families, and checksums
do not depend on iteration order.

## 3. Atomic role activation

Role activation is a full-set replacement command:

```text
expected authVersion
  -> user authorization row lock
  -> canonical roots
  -> assignment evidence
  -> disabled/expiry/prerequisite checks
  -> same-APP DSD/mutex check
  -> root count limit
  -> permission/scope/field merge
  -> immutable snapshot
  -> authVersion CAS
  -> Redis projection
```

The same normalized root set is idempotent. A different request using a stale
`authVersion` fails with a conflict. No partial root activation is committed.
If the client loses the response, it reads the current set and compares the
server result before deciding whether another request is necessary.

## 4. Authorization algebra

### 4.1 Function permissions

Function permissions are a set union across all active root families. Union is
commutative, associative, and idempotent, which guarantees stable decisions for
equivalent active sets.

### 4.2 Data scopes

Data scopes are merged by the typed scope merger registered for the resource
kind. A merger returns a canonical scope expression and evidence. It may widen
only according to an explicit rule; an unknown scope type fails closed.

### 4.3 Field access

Field rules use a stable resource/field key. Denial and masking constraints are
preserved during merge; sensitive fields default to `NONE`. Output is sorted by
stable field key so serialization and checksums are deterministic.

### 4.4 Operation SOD and participation

Operation SOD is checked against the effective operation and business object.
Participation facts are append-only, tenant-scoped, serialized by business
event identity, and queried without exposing unrelated object history.

## 5. Runtime consistency and failure behavior

Reference JWTs contain identity claims, not an embedded permission list. The PEP validates:

1. one syntactically valid Bearer credential;
2. trusted RS256 issuer, audience, `kid`, signature and time claims;
3. exact Tenant, Tianquan-Shoubing subject, authentication context and policy versions;
4. an unexpired immutable authorization snapshot;
5. no closed mutation Fence for the protected scope;
6. typed Function/Data/Field/Participation decision.

Missing state, Redis errors, untrusted keys, version drift, unknown mappings and
rule errors deny access. A bounded last-known-good public-key cache may cover a
temporary key-source failure, but never version or authorization state drift.

The resource-service Starter validates the original Bearer credential and
enforces the current authorization decision at the protected method or data
boundary. The runtime authorization client uses a fixed deployment binding for
current state. Missing evidence or an unavailable authority prevents execution.

## 6. Persistence and delivery

Tianquan-Jianshen and Transactional Outbox use one PostgreSQL DataSource but separate
Flyway locations and history tables. Tianquan-Jianshen has one immutable V1 migration; new
schema changes require the next migration and must never rewrite V1.

Authorization mutations and outbox records are written in the business
transaction. Workers claim bounded batches with PostgreSQL locking semantics,
publish deterministic Redis snapshots, persist checkpoints, and open Fences
only after the projection succeeds. Retry is bounded and mutation-addressable;
the UI cannot issue a broad “retry everything” command.

## 7. Selected design patterns

| Pattern            | Where used                                                                  | Why it fits                                                                                                       |
|--------------------|-----------------------------------------------------------------------------|-------------------------------------------------------------------------------------------------------------------|
| Specification      | SSD/DSD, prerequisite, cardinality, self-assignment and operation-SOD rules | Rules are independently testable predicates with explicit evidence and denial codes                               |
| Strategy           | Password authentication, Data Scope merger, Field Rule merger               | These are known variation points; direct conditional chains would couple unrelated algorithms                     |
| Domain Service     | Graph validation, activation resolution, authorization decision             | The operation spans multiple domain facts but does not belong to one entity                                       |
| Facade             | Assignment, Manifest, Management Policy, activation, simulation             | Keeps HTTP orchestration out of domain algorithms and provides one transaction boundary                           |
| Ports and Adapters | Database clock, locks, query stores, Redis projection, Tianshu/Yuheng status   | Core/application code depends on capabilities, while infrastructure details remain replaceable in tests           |
| State              | Mutation/fence status and runtime publication status                        | Transitions and illegal moves are explicit rather than scattered boolean combinations                             |
| Adapter            | Resource Starter and the exact Tianshu policy applier               | Translates host/configuration contracts into typed policy behavior without duplicating their lifecycle algorithms |
| Observer           | Optional Micrometer apply observer                                          | Adds fixed-cardinality success/failure evidence without making configuration delivery depend on metrics           |
| Immutable Snapshot | Runtime policy and authorization snapshot publication                       | One reference swap gives command-scoped consistency and preserves a last-known-good value on validation failure   |

A general-purpose rule engine, abstract factory hierarchy, event-sourced aggregate,
and chain class per authorization step were rejected. The rule set is typed and
known, transactions are relational, and direct ordered orchestration is clearer
and safer than runtime-configurable indirection.

## 8. Complexity and capacity controls

- Role graph traversal: `O(V + E)` under configured role/edge/depth limits.
- Permission merge: `O(P log P)` from canonical sorting; membership is set based.
- Snapshot and runtime authorization lookup use bounded reads and deadlines.
- Assignment/participation capacity: serialized by stable PostgreSQL lock keys.
- Admin list/audit APIs: bounded cursor/page sizes and query-count tests.
- Workers: bounded batch size and concurrency, SKIP LOCKED ownership, retry state.
- Active roles: maximum active roots and assignment/activation constraints.

Wall-clock assertions are opt-in (`tianquan-jianshen.performance.enforce`) because shared CI
latency is not a stable performance oracle. Default tests assert deterministic
operation/query budgets; controlled environments may add calibrated time limits.
