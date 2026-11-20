# Tianquan-Jianshen Security Boundaries

## 1. Trust zones

| Boundary | Trusted input | Validation |
| --- | --- | --- |
| Public client → Cilium Gateway | Public HTTPS host and approved HTTPRoute | Match the approved host, path and method and select its Service. |
| Gateway → resource service | HTTP request and Bearer intended for the resource | The resource Starter verifies issuer, audience, tenant, token status and applicable authorization before processing. |
| Resource service → runtime authorization API | Approved SERVICE credential and explicit binding | Require the expected operation and policy versions. Treat missing, invalid or fenced evidence as a refusal. |
| Trusted producer → manifest API | Scoped SERVICE identity and tenant/application binding | Validate immutable manifest content, producer and deployment evidence. |
| Jianshen → Yuheng Admin | HMAC credential scoped to definition reporting | Validate the report identity and scope. Status reads use their own OAuth credential. |
| Jianshen → Tianshu configuration API | Scoped SERVICE token and projected workload token | Verify the bound workload identity and configuration scope. |
| Admin → PostgreSQL/Redis | Named deployment-owned clients | Restrict each role to its assigned data store and credentials. |

## 2. Tenant and APP isolation

The authenticated principal owns the normal tenant context. A target tenant is
accepted only on xingyuan administration routes, through
`X-Tianquan-Jianshen-Target-Tenant`, and only with the xingyuan permission. Path tenant,
target header and effective tenant must agree. Repositories include tenant in
every lookup and mutation key.

Service identities are additionally scoped to tenant and APP. Internal APIs do
not allow a trusted service for APP A to obtain decisions or snapshots for APP B.

## 3. Credential handling

- Browser clients use PUBLIC authorization-code flow with S256 PKCE and get a
  bearer issued for the target Resource. At expiry, the browser starts a new
  authorization exchange through Shoubing.
- Shoubing owns signing keys, JWKS and authoritative token status. Jianshen
  verifies public claims and the current state through its configured authority
  binding. The audit cursor uses its own file-backed secret.
- Yuheng report credentials, status-read tokens and Tianshu configuration
  credentials each have their own scope and lifecycle.
- Logs, UI errors, audit details and verification evidence redact Authorization,
  cookies, passwords, key material and sensitive field values recursively.

## 4. Fail-closed matrix

Access is denied for malformed/multiple Bearer credentials, unknown `kid`, bad
signature, issuer/audience/time mismatch, expired Access Token, disabled User/Tenant,
auth or policy version drift, missing/expired Redis snapshot, closed Fence,
unknown Yuheng operation mapping, unavailable non-covered key source, invalid
Data/Field rule, Participation conflict, or internal dependency error.

A cached public key can be last-known-good only for its bounded validity window.
It never authorizes a missing authorization snapshot or bypasses a Fence.

## 5. Privilege change protections

- Assignment is not activation.
- Self-assignment and privileged-role assignment require explicit policy.
- One complete Management Policy must cover subject, target scope, role root and
  operation; policy fragments are never composed.
- SSD constrains qualification. DSD and same-APP mutex constrain active role sets.
- Optimistic versions, PostgreSQL locks and stable capacity keys serialize
  concurrent changes.
- Idempotency keys are stored with request hashes; reuse with changed content is
  rejected.
- Audit facts are append-only and read access is itself audited.

## 6. Data and field enforcement

Clients cannot enforce Data or Field security. The decision supplies canonical
scope/filter evidence, and the server applies it before returning results.
Sensitive fields default to no access. Masked responses never include the raw
value in hidden DOM state or alternate JSON fields.

## 7. Network and operational controls

Cilium Gateway terminates public HTTPS. The approved upstream Service uses
HTTP inside the cluster. Namespace and workload policies and host firewalls
restrict internal authorization, manifest, Tianshu configuration and Yuheng
reporting endpoints. Cross-node traffic uses the platform WireGuard policy.
Resources still enforce OAuth and authorization. Set bounded connect and read
timeouts, payload limits, worker concurrency and retry backoff.

Verification scripts accept only explicit URLs and secret files. Fixture cleanup
accepts a strict schema/prefix and exact keys from a non-symbolic-link state
file. Scripts do not control service processes.

## 8. Residual evidence limits

Unit and integration tests do not demonstrate the user's TLS, firewall, secret
permissions, PostgreSQL isolation, Redis ACL, clock synchronization, multi-node
Snowflake allocation, Tianshu snapshot convergence or Cilium route failover. Those controls need
deployment review and recorded live evidence.
