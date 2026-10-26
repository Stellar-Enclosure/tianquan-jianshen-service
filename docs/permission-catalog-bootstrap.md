# Explicit permission catalog B0 and administrator B1

Clean-environment initialization has this order: migrate the approved schemas and prepare an ACTIVE IdP realm; run IdP B0 for finite clients/resources/grants; run META B0 and RBAC B0 with the same six-part target and public business/application IDs; register every FULL producer and obtain matching source receipts; obtain deployment qualifications and activate the complete producer set; run RBAC B1 for a reviewed list of active permission codes. See the [catalog protocol](permission-catalog-api.md) and [controlled delivery](permission-ci.md) for registration and activation.

The two commands below are explicit operator commands in the verified Admin executable. They are not application startup hooks, HTTP endpoints or ordinary CI jobs; `CI=true` is rejected. The dedicated non-web context contains only persistence, ID generation, append audit and Outbox production. It starts no web server, RPC provider, scheduler or delivery consumer. It does not run migrations or infer connection settings from application YAML, environment variables or system properties. The legacy `bootstrap-platform-admin` command does not establish the new catalog or grant its permission codes and is not the clean-environment permission bootstrap path.

Prepare a private directory with mode `0700` and command, connection and password files with mode `0600`, owned by the executing OS user. Every path must be absolute and normalized; input files and their immediate parent must not be symlinks. The receipt parent must already exist with the same owner-only permissions. Passwords belong only in the private password file. Do not include them in argv, environment, a JDBC URL, command JSON or logs. One optional trailing LF/CRLF in the password file is stripped.

The connection file is explicit:

```json
{
  "jdbcUrl": "jdbc:postgresql://db.example:5432/rbac",
  "databaseName": "rbac",
  "databaseOid": "42001",
  "databaseOwner": "approved_rbac_owner",
  "username": "approved_rbac_owner",
  "passwordFile": "/absolute/private/rbac-db-password",
  "idMachineId": 7,
  "schema": "public"
}
```

Replace the example OID, database owner and all target IDs with the reviewed environment's actual facts; do not guess them. The URL accepts a PostgreSQL host/port and explicit database name, without query credentials or arbitrary options. Every physical connection checks `current_database()`, database OID, database owner, `current_user` and `current_schema()`. Owner and connecting user must match. Before opening the persistence context the command verifies a successful V16 entry in `public.flyway_schema_history_rbac3`. Existing SQL and Outbox histories are prerequisites, never rewritten by this command. `idMachineId` is the explicitly allocated Common Snowflake machine ID (0–1023), not a generated target identity.

The context reuses the checked-in native routing topology with the single physical primary `rbac_primary`. JPA, audit SQL and transactional Outbox use exactly the same logical `dataSource` and `transactionManager`. Outbox DDL initialization and business state-machine execution are disabled. A different physical topology requires its reviewed owner initialization; this command does not infer a shard from user data.

## B0: catalog source authority

The command JSON has this exact shape. Examples are not deployable configuration; each client must have matching IdP resource/scopes established by IdP B0.

```json
{
  "schemaVersion": 1,
  "operationId": "1ba7dd19-18ef-40c0-a6dc-74f8a8183ff6",
  "connectionFile": "/absolute/private/rbac-database.json",
  "target": {
    "catalogScopeId": "10001", "tenantId": "20001",
    "businessCode": "xingyuan", "applicationCode": "tianquan-jianshen",
    "namespaceCode": "default", "environment": "test"
  },
  "applicationId": "30001",
  "applicationName": "Tianquan Jianshen",
  "ddcBusinessId": "reviewed-business-public-id",
  "ddcApplicationId": "reviewed-application-public-id",
  "producers": [{
    "producerId": "tianquan-jianshen-java", "kind": "JAVA",
    "ownedKeyPrefixes": ["tianquan-jianshen.api.", "tianquan-jianshen.field."],
    "ownedPermissionPrefixes": ["system:"],
    "ownedMessagePrefixes": ["permission."],
    "expectedModules": ["stellar-enclosure-tianquan-jianshen-admin"],
    "serviceGrants": [{
      "issuer": "https://idp.example/tenants/20001",
      "clientId": "reviewed-registration-client", "resourceUri": "https://rbac.example",
      "capabilities": ["REGISTER", "READ_DESCRIPTOR"],
      "allowedSourceRefs": ["refs/heads/main"], "allowPermissionExpansion": false
    }, {
      "issuer": "https://idp.example/tenants/20001",
      "clientId": "reviewed-deployment-authority", "resourceUri": "https://rbac.example",
      "capabilities": ["QUALIFY_DEPLOYMENT", "ACTIVATE", "READ_DESCRIPTOR"],
      "allowedSourceRefs": ["refs/heads/main"], "allowPermissionExpansion": false
    }]
  }]
}
```

Use a fresh canonical UUID for each new operation and preserve it for recovery. Producer kind is a defined Manifest kind (`JAVA` or `REACT_TYPESCRIPT`). Prefixes must end at `.`/`:`/`/` namespace boundaries and must not overlap another owner's prefixes, ignoring case. Supply the exact successful module inventory from the producer artifact. A producer accepts 1–16 finite service identities; the command accepts 1–32 producers. Capabilities are only `REGISTER`, `ACTIVATE`, `READ_DESCRIPTOR`, `QUALIFY_DEPLOYMENT`, and `CLEAR_PRODUCER`, with matching finite IdP scopes. `allowPermissionExpansion=true` requires an explicit `ACTIVATE` grant. Only a reviewed activation authority receives expansion/clear authority; registration does not imply either.

```bash
java -jar stellar-enclosure-tianquan-jianshen-admin/target/stellar-enclosure-tianquan-jianshen-admin-exec.jar \
  bootstrap-permission-catalog \
  --command-file /absolute/private/rbac-catalog-command.json \
  --receipt-file /absolute/private/rbac-catalog-receipt.json
```

B0 creates or exactly checks the ACTIVE application/public-ID binding, six-part catalog scope, zero active pointer, producer owners and finite service grants, plus the tenant authorization-state prerequisite. It creates no resource, permission, role, user or assignment. Existing disabled owners/grants, altered revisions, conflicting IDs/bindings or overlapping prefixes fail. It never overwrites or re-enables an existing fact. A catalog with an active revision cannot be initialized by a different B0 operation.

## B1: finite administrator grant

Only proceed after the exact target has an active catalog. Read the actual active revision and review the permission definitions first. Every code must be explicitly listed, currently selected by the active catalog, and have ACTIVE governance state; wildcard, unknown, unactivated, disabled or retired codes are rejected. The command checks all current producer owners are enabled and all active members have matching READY manifests and exact deployment qualification digests/build/commit. Qualification validity is checked at the recorded activation time, as in ordinary runtime binding; its later TTL expiry does not independently deactivate an admitted build.

```json
{
  "schemaVersion": 1,
  "operationId": "1a920c21-5892-4f3f-846a-da20ff64d73d",
  "connectionFile": "/absolute/private/rbac-database.json",
  "target": {
    "catalogScopeId": "10001", "tenantId": "20001",
    "businessCode": "xingyuan", "applicationCode": "tianquan-jianshen",
    "namespaceCode": "default", "environment": "test"
  },
  "expectedActiveRevision": "1",
  "identitySub": "reviewed-existing-idp-subject",
  "roleCode": "INITIAL_PERMISSION_ADMIN", "roleName": "Initial permission administrator",
  "permissionCodes": ["system:permission-catalog:read", "system:role-permission:read"],
  "validFrom": null, "validTo": null, "activateRole": true
}
```

The example intentionally grants only the listed reads; add any needed management and FIELD read/write codes only after reviewing their active definitions. Null `validFrom` means transaction time. A finite `validTo` must be after the start and current transaction time. Future assignment starts are allowed only when `activateRole=false`. Include the nullable fields as shown; missing, unknown, duplicate or type-coerced JSON fields are rejected.

```bash
java -jar stellar-enclosure-tianquan-jianshen-admin/target/stellar-enclosure-tianquan-jianshen-admin-exec.jar \
  bootstrap-permission-admin \
  --command-file /absolute/private/rbac-admin-command.json \
  --receipt-file /absolute/private/rbac-admin-receipt.json
```

B1 is one-time per catalog scope. It creates a fresh MANAGEMENT/CRITICAL role with self closure, no inheritance or constraints, an exact permission-code grant and one DIRECT assignment for the explicitly chosen subject. It creates the local authorization user only if missing; disabled users fail. Missing tenant-application and business-access entitlements can be created for this interval. Existing facts must already provide effective access; they are never repaired or re-enabled. Independent business-access sources keep the normal any-effective-source semantics and retain their individual revocations. User authVersion, tenant policy version, audit and Outbox publication commit in that same transaction. If `activateRole=true`, the user must have no current active role in this application; activation of this fresh root preserves active roles in all other applications. `false` leaves the active role set unchanged. A different later operation cannot add permissions or initialize a second bootstrap role for that scope; use the normal protected administration flow after bootstrap.

## Original receipt and acceptance boundary

Both stages serialize by tenant advisory transaction lock, append `PERMISSION_CATALOG_BOOTSTRAPPED` or `PERMISSION_ADMIN_BOOTSTRAPPED` in `rbac3_audit_log`, and retain the command digest plus original secret-free receipt. The canonical digest binds the complete command and non-secret database identity, including OID/owner. The local mode-0600 receipt is published only after commit and never overwritten with different content.

For timeout, unknown commit outcome or failed local receipt publication, retain the command, database identity and operation UUID, then rerun exactly that operation. The database audit is authoritative: a matching original receipt is returned without re-enabling owners, recreating assignments or reapplying activation. A changed digest, conflicting local receipt or local receipt with no committed matching audit fails. The command prints only a fixed success/failure message and does not print database/driver exception text.

Unit/context tests exercise strict file/JSON validation, database identity checks with mocked JDBC, same DataSource/TM wiring, finite owner/grant persistence, one-time role/activation rules, conflict/replay recovery, audit and Outbox failure propagation. They do not establish real PostgreSQL routing, FK/trigger/rollback behavior, cross-center B0 → registration → activation → B1, service startup or management UI acceptance. No bootstrap command has been executed against a database by this implementation task.
