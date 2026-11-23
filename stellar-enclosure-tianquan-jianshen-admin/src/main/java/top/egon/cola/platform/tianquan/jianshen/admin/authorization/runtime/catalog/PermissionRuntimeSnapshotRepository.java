package top.egon.cola.platform.tianquan.jianshen.admin.authorization.runtime.catalog;

import com.fasterxml.jackson.databind.ObjectMapper;
import jakarta.persistence.EntityManager;
import org.springframework.stereotype.Repository;
import org.springframework.transaction.annotation.Transactional;
import top.egon.cola.component.common.id.snowflake.SnowflakeIdGenerator;
import top.egon.cola.platform.tianquan.jianshen.admin.authorization.runtime.activation.repository.RoleActivationFactRepository;
import top.egon.cola.platform.tianquan.jianshen.admin.authorization.runtime.activation.repository.ActivationTransaction;
import top.egon.cola.platform.tianquan.jianshen.admin.iam.role.service.RoleEligibilityService;
import top.egon.cola.platform.tianquan.jianshen.admin.shared.domain.DatabaseClock;
import top.egon.cola.platform.tianquan.jianshen.admin.shared.tenant.domain.CatalogProjectionTenantContext;
import top.egon.cola.platform.tianquan.jianshen.contract.authorization.RuntimePolicyBinding;
import top.egon.cola.platform.tianquan.jianshen.contract.authorization.SystemAuthorizationSnapshot;
import top.egon.cola.platform.tianquan.jianshen.contract.permission.CanonicalJson;
import top.egon.cola.platform.tianquan.jianshen.contract.permission.CatalogScope;
import top.egon.cola.platform.tianquan.jianshen.contract.permission.EffectivePermissionSnapshot;
import top.egon.cola.platform.tianquan.jianshen.core.activation.DefaultRoleActivationResolver;
import top.egon.cola.platform.tianquan.jianshen.core.activation.RoleActivationInput;
import top.egon.cola.platform.tianquan.jianshen.core.rule.Rbac3RuleViolation;
import java.time.Instant;
import java.util.List;
import java.util.Map;
import java.util.Set;

/** Reads the authority and publishes its derived immutable snapshot/head in one local PostgreSQL transaction. */
@Repository
public class PermissionRuntimeSnapshotRepository {
    private final EntityManager entityManager;
    private final ObjectMapper mapper;
    private final RoleActivationFactRepository facts;
    private final ActivationTransaction activeRoles;
    private final RoleEligibilityService eligibility;
    private final DatabaseClock clock;
    private final PermissionRuntimeProperties properties;
    private final java.util.function.LongSupplier ids;

    @org.springframework.beans.factory.annotation.Autowired
    public PermissionRuntimeSnapshotRepository(EntityManager entityManager, ObjectMapper mapper,
            RoleActivationFactRepository facts, ActivationTransaction activeRoles, RoleEligibilityService eligibility,
            DatabaseClock clock, PermissionRuntimeProperties properties) {
        this(entityManager, mapper, facts, activeRoles, eligibility, clock, properties, SnowflakeIdGenerator::nextLongId);
    }

    PermissionRuntimeSnapshotRepository(EntityManager entityManager, ObjectMapper mapper,
            RoleActivationFactRepository facts, ActivationTransaction activeRoles, RoleEligibilityService eligibility,
            DatabaseClock clock, PermissionRuntimeProperties properties, java.util.function.LongSupplier ids) {
        this.ids = ids;
        this.entityManager = entityManager;
        this.mapper = mapper;
        this.facts = facts;
        this.activeRoles = activeRoles;
        this.eligibility = eligibility;
        this.clock = clock;
        this.properties = properties;
    }

    @Transactional
    public SystemAuthorizationSnapshot current(PermissionRuntimeProofService.VerifiedRequest request) {
        return build(request.binding(), request.issuer().toASCIIString(), request.user().subject(), request.user().expiresAt(), null);
    }

    /** Reads the activated resource policy in the same transaction as the current subject snapshot. */
    @Transactional
    ExecutionView currentExecution(ExecutionGrantAuthorizationService.VerifiedExecution request) {
        var snapshot = build(request.binding(), request.issuer().toASCIIString(), request.subject(), request.expiresAt(), null);
        return new ExecutionView(snapshot, executionResource(request.binding(), snapshot.permissionSnapshot().catalogVersion(), request.resourceKey()));
    }

    /** Reads a SERVICE policy and its activated resource without creating a USER snapshot. */
    @Transactional
    ServiceExecutionView currentServiceExecution(PermissionRuntimeProperties.Binding binding, Instant expiresAt, String resourceKey) {
        var snapshot = policy(binding, expiresAt);
        return new ServiceExecutionView(snapshot, executionResource(binding, snapshot.catalogVersion(), resourceKey));
    }

    private top.egon.cola.platform.tianquan.jianshen.contract.permission.PermissionManifest.ResourceDefinition executionResource(
            PermissionRuntimeProperties.Binding binding, String catalogVersion, String resourceKey) {
        Object[] row = one("""
                select cast(rv.definition_json as text), rv.definition_digest
                  from rbac3_catalog_activation_producer ap
                  join rbac3_catalog_producer p on p.catalog_scope_id = ap.catalog_scope_id and p.producer_id = ap.producer_id and p.enabled
                  join rbac3_catalog_resource_version rv on rv.catalog_scope_id = ap.catalog_scope_id and rv.producer_id = ap.producer_id
                       and rv.producer_version = ap.producer_version
                  join rbac3_catalog_resource r on r.catalog_scope_id = rv.catalog_scope_id and r.id = rv.resource_id
                 where ap.catalog_scope_id = :scope and ap.activation_version = :catalog and ap.producer_id = :producer
                   and ap.producer_version = :version and rv.registration_key = :key and r.governance_state = 'ACTIVE'
                """, Map.of("scope", Long.parseLong(binding.scope().catalogScopeId()),
                "catalog", Long.parseLong(catalogVersion), "producer", binding.producerId(),
                "version", Long.parseLong(binding.producerVersion()), "key", resourceKey),
                "AUTH_RUNTIME_EXECUTION_POLICY_UNAVAILABLE");
        try {
            String json = text(row[0]);
            Map<?, ?> encoded = mapper.readValue(json, Map.class);
            if (!CanonicalJson.digest(encoded).equals(text(row[1]).trim())) {
                throw new Rbac3RuleViolation("AUTH_RUNTIME_CHECKSUM_MISMATCH");
            }
            top.egon.cola.platform.tianquan.jianshen.contract.permission.PermissionManifest.ResourceDefinition resource = mapper
                    .readerFor(top.egon.cola.platform.tianquan.jianshen.contract.permission.PermissionManifest.ResourceDefinition.class)
                    .with(com.fasterxml.jackson.databind.DeserializationFeature.FAIL_ON_UNKNOWN_PROPERTIES,
                            com.fasterxml.jackson.databind.DeserializationFeature.FAIL_ON_TRAILING_TOKENS)
                    .with(com.fasterxml.jackson.core.JsonParser.Feature.STRICT_DUPLICATE_DETECTION).readValue(json);
            return resource;
        } catch (com.fasterxml.jackson.core.JsonProcessingException | IllegalArgumentException invalid) {
            throw new Rbac3RuleViolation("AUTH_RUNTIME_PAYLOAD_INVALID");
        }
    }

    record ExecutionView(SystemAuthorizationSnapshot snapshot,
                         top.egon.cola.platform.tianquan.jianshen.contract.permission.PermissionManifest.ResourceDefinition resource) { }
    record ServiceExecutionView(top.egon.cola.platform.tianquan.jianshen.contract.authorization.ServicePolicySnapshot snapshot,
                                top.egon.cola.platform.tianquan.jianshen.contract.permission.PermissionManifest.ResourceDefinition resource) { }

    /** Background publication uses database subjects and the configured trusted issuer; it does not create a USER principal. */
    @Transactional
    public void rebuild(PermissionRuntimeProperties.Binding binding, long userId, PermissionSnapshotRebuildRepository.Task task) {
        requireRebuildOwner(task, true);
        Object[] user = one("select identity_sub from rbac3_user where tenant_id = :tenant and id = :user and status = 'ACTIVE'",
                Map.of("tenant", Long.parseLong(binding.scope().tenantId()), "user", userId), "IDENTITY_INACTIVE");
        build(binding, binding.serviceIssuer().toASCIIString(), text(user[0]), clock.transactionNow().plus(properties.snapshotTtl()), task);
    }

    private SystemAuthorizationSnapshot build(PermissionRuntimeProperties.Binding binding, String issuer, String subject, Instant proofExpiresAt,
                                               PermissionSnapshotRebuildRepository.Task task) {
        CatalogScope scope = binding.scope();
        long scopeId = Long.parseLong(scope.catalogScopeId());
        long tenantId = Long.parseLong(scope.tenantId());
        Instant now = clock.transactionNow();
        if (!proofExpiresAt.isAfter(now)) throw new Rbac3RuleViolation("JWT_EXPIRED");
        PolicyState state = policyState(binding);
        long policyVersion = state.policyVersion();
        long catalogVersion = state.catalogVersion();
        Object[] user = one("""
                select id, auth_version from rbac3_user
                where tenant_id = :tenant and identity_sub = :subject and status = 'ACTIVE' for share
                """, Map.of("tenant", tenantId, "subject", subject), "IDENTITY_INACTIVE");
        long userId = number(user[0]);
        long authVersion = number(user[1]);
        var fact = CatalogProjectionTenantContext.call(scope.tenantId(), () -> {
            if (!eligibility.isEffectiveForProjection(scope.tenantId(), Long.toString(userId),
                    Long.toString(state.applicationId()), now)) {
                throw new Rbac3RuleViolation("APPLICATION_BINDING_DENIED");
            }
            return facts.load(scope.tenantId(), Long.toString(userId), now);
        });
        if (fact.authVersion() != authVersion || fact.policyVersion() != policyVersion) {
            throw new Rbac3RuleViolation("AUTH_RUNTIME_VERSION_CONFLICT");
        }
        var selected = activeRoles.current(scope.tenantId(), subject, Long.toString(userId), now);
        List<String> allRoots = selected.rootsByApplication().values().stream().flatMap(Set::stream).distinct().sorted().toList();
        List<String> roots = selected.rootsByApplication().getOrDefault(Long.toString(state.applicationId()), Set.of()).stream().sorted().toList();
        List<String> roles = List.of();
        if (!allRoots.isEmpty()) {
            var resolution = new DefaultRoleActivationResolver().resolve(new RoleActivationInput(scope.tenantId(),
                    Long.toString(userId), allRoots, fact.assignments(), fact.hierarchy(), fact.dsdSets(),
                    fact.authorizationFacts(), authVersion, policyVersion, now));
            if (!resolution.activeRoleSet().rootIds().equals(Set.copyOf(allRoots))) {
                throw new Rbac3RuleViolation("ROLE_ACTIVATION_SET_INVALID");
            }
            roles = resolution.snapshot().effectiveRoleIds().stream()
                    .filter(role -> Long.toString(state.applicationId()).equals(fact.hierarchy().requireNode(role).applicationId())).sorted().toList();
        }
        List<String> permissions = permissions(scopeId, catalogVersion, roles, now);
        Set<String> resources = resources(scopeId, catalogVersion);
        Instant expiresAt = now.plus(properties.snapshotTtl());
        if (proofExpiresAt.isBefore(expiresAt)) expiresAt = proofExpiresAt;
        var view = new EffectivePermissionSnapshot(issuer, subject, scope,
                Long.toString(catalogVersion), Long.toString(authVersion), Long.toString(policyVersion),
                new EffectivePermissionSnapshot.ActiveRoleContext(scope.applicationCode(), roots, roles), permissions, expiresAt);
        var build = new RuntimePolicyBinding(binding.producerId(), binding.producerVersion(), binding.artifactDigest(),
                binding.policyDigest(), binding.manifestDigest());
        if (task != null) requireRebuildOwner(task, false);
        view = publish(view, userId, now);
        expiresAt = view.snapshotExpiresAt();
        String digest = CanonicalJson.digest(mapper.convertValue(view, Map.class));
        return new SystemAuthorizationSnapshot(scope.tenantId(), view.subject(), Long.toString(userId), scope.applicationCode(),
                authVersion, policyVersion, roles, null, null, Set.copyOf(permissions), resources,
                dataScopes(scopeId, userId, roles, permissions, authVersion, policyVersion, scope.tenantId(), now),
                Map.of(), digest, now, expiresAt, view, build);
    }

    @Transactional
    public top.egon.cola.platform.tianquan.jianshen.contract.authorization.ServicePolicySnapshot policy(
            PermissionRuntimeProperties.Binding binding, Instant credentialExpiresAt) {
        var state = policyState(binding);
        Instant now = clock.transactionNow();
        Instant expires = now.plus(properties.snapshotTtl());
        if (credentialExpiresAt.isBefore(expires)) expires = credentialExpiresAt;
        if (!expires.isAfter(now)) throw new Rbac3RuleViolation("JWT_EXPIRED");
        return new top.egon.cola.platform.tianquan.jianshen.contract.authorization.ServicePolicySnapshot(
                binding.scope(), Long.toString(state.catalogVersion()), Long.toString(state.policyVersion()),
                new RuntimePolicyBinding(binding.producerId(), binding.producerVersion(), binding.artifactDigest(),
                        binding.policyDigest(), binding.manifestDigest()), resources(Long.parseLong(binding.scope().catalogScopeId()),
                        state.catalogVersion()), expires);
    }

    private PolicyState policyState(PermissionRuntimeProperties.Binding binding) {
        CatalogScope scope = binding.scope();
        long scopeId = Long.parseLong(scope.catalogScopeId());
        long tenantId = Long.parseLong(scope.tenantId());
        Object[] scopeRow = one("""
                select s.id, s.tenant_id, s.business_code, s.application_code, s.namespace_code, s.environment,
                       s.application_id from rbac3_catalog_scope s join rbac3_application a on a.id = s.application_id
                where s.id = :scope and s.status = 'ACTIVE' and a.status = 'ACTIVE'
                  and a.application_code = s.application_code and a.ddc_business_id = s.ddc_business_id
                  and a.ddc_application_id = s.ddc_application_id for share of s
                """, Map.of("scope", scopeId), "APPLICATION_BINDING_DENIED");
        CatalogScope stored = new CatalogScope(text(scopeRow[0]), text(scopeRow[1]), text(scopeRow[2]),
                text(scopeRow[3]), text(scopeRow[4]), text(scopeRow[5]));
        if (!scope.equals(stored)) throw new Rbac3RuleViolation("APPLICATION_BINDING_DENIED");
        // Every catalog mutation takes scope before tenant state. Readers use the same order.
        long policyVersion = number(one("select policy_version from rbac3_tenant_authorization_state where tenant_id = :tenant for share",
                Map.of("tenant", tenantId), "AUTH_RUNTIME_UNAVAILABLE")[0]);
        Object[] deployed = one("""
                select a.activation_version, a.policy_version, ap.producer_version, ap.manifest_digest,
                       ap.policy_digest, q.artifact_digest, a.created_at, q.verified_at, q.expires_at
                  from rbac3_catalog_active_pointer p
                  join rbac3_catalog_activation a on a.catalog_scope_id = p.catalog_scope_id and a.activation_version = p.activation_version
                  join rbac3_catalog_activation_producer ap on ap.catalog_scope_id = a.catalog_scope_id and ap.activation_version = a.activation_version
                  join rbac3_catalog_producer producer on producer.catalog_scope_id = ap.catalog_scope_id and producer.producer_id = ap.producer_id
                  join rbac3_catalog_manifest m on m.catalog_scope_id = ap.catalog_scope_id and m.producer_id = ap.producer_id and m.producer_version = ap.producer_version
                  join rbac3_catalog_deployment_qualification q on q.catalog_scope_id = ap.catalog_scope_id and q.producer_id = ap.producer_id
                       and q.producer_version = ap.producer_version and q.id = ap.qualification_id
                 where p.catalog_scope_id = :scope and ap.producer_id = :producer and producer.enabled
                   and m.state = 'READY' and q.manifest_digest = ap.manifest_digest and q.policy_digest = ap.policy_digest
                """, Map.of("scope", scopeId, "producer", binding.producerId()), "AUTH_SNAPSHOT_NOT_READY");
        long catalogVersion = number(deployed[0]);
        if (!binding.producerVersion().equals(text(deployed[2])) || !binding.manifestDigest().equals(text(deployed[3]).trim())
                || !binding.policyDigest().equals(text(deployed[4]).trim()) || !binding.artifactDigest().equals(text(deployed[5]).trim())
                || number(deployed[1]) > policyVersion
                || instant(deployed[6]).isBefore(instant(deployed[7]))
                || !instant(deployed[6]).isBefore(instant(deployed[8]))) {
            var denied = new Rbac3RuleViolation("AUTH_DEPLOYMENT_BINDING_MISMATCH");
            if (binding.local()) {
                try {
                    var failedChecks = new java.util.ArrayList<String>();
                    if (!binding.producerVersion().equals(text(deployed[2]))) failedChecks.add("PRODUCER_VERSION_MISMATCH");
                    if (!binding.manifestDigest().equals(text(deployed[3]).trim())) failedChecks.add("MANIFEST_DIGEST_MISMATCH");
                    if (!binding.policyDigest().equals(text(deployed[4]).trim())) failedChecks.add("POLICY_DIGEST_MISMATCH");
                    if (!binding.artifactDigest().equals(text(deployed[5]).trim())) failedChecks.add("ARTIFACT_DIGEST_MISMATCH");
                    if (number(deployed[1]) > policyVersion) failedChecks.add("ACTIVATION_POLICY_AHEAD");
                    if (instant(deployed[6]).isBefore(instant(deployed[7]))) failedChecks.add("QUALIFICATION_AFTER_ACTIVATION");
                    if (!instant(deployed[6]).isBefore(instant(deployed[8]))) failedChecks.add("QUALIFICATION_EXPIRED_AT_ACTIVATION");
                    var selected = new RuntimePolicyBinding(binding.producerId(), text(deployed[2]), text(deployed[5]).trim(),
                            text(deployed[4]).trim(), text(deployed[3]).trim());
                    denied.initCause(new top.egon.cola.platform.tianquan.jianshen.starter.permission.RuntimeBindingMismatchEvidence(
                            scope, Long.toString(catalogVersion), Long.toString(policyVersion), selected,
                            Map.of("producerId", binding.producerId(), "producerVersion", binding.producerVersion(),
                                    "artifactDigest", binding.artifactDigest(), "policyDigest", binding.policyDigest(),
                                    "manifestDigest", binding.manifestDigest()), failedChecks));
                } catch (RuntimeException diagnosticFailure) {
                    org.slf4j.LoggerFactory.getLogger(PermissionRuntimeSnapshotRepository.class).warn(
                            "Runtime binding diagnostic unavailable failureType={}", diagnosticFailure.getClass().getSimpleName());
                }
            }
            throw denied;
        }
        return new PolicyState(number(scopeRow[6]), catalogVersion, policyVersion);
    }

    private record PolicyState(long applicationId, long catalogVersion, long policyVersion) { }

    private void requireRebuildOwner(PermissionSnapshotRebuildRepository.Task task, boolean lock) {
        one("""
                select id from rbac3_catalog_rebuild_task where id = :id and state = 'RUNNING'
                  and owner = :owner and lease_token = :token and lease_generation = :generation
                  and lease_until > clock_timestamp()
                """ + (lock ? " for share" : ""), Map.of("id", task.id(), "owner", task.owner(),
                "token", task.token(), "generation", task.generation()), "AUTH_REBUILD_CLAIM_LOST");
    }

    private List<String> permissions(long scope, long catalog, List<String> roles, Instant now) {
        if (roles.isEmpty()) return List.of();
        return rows("""
                select distinct p.permission_code as permission_code from rbac3_catalog_role_permission g
                  join rbac3_catalog_role_binding b on b.catalog_scope_id = g.catalog_scope_id and b.role_id = g.role_id and b.enabled
                  join rbac3_catalog_permission p on p.catalog_scope_id = g.catalog_scope_id and p.id = g.permission_id and p.governance_state = 'ACTIVE'
                  join rbac3_catalog_activation_producer ap on ap.catalog_scope_id = p.catalog_scope_id and ap.producer_id = p.owner_producer_id
                  join rbac3_catalog_producer producer on producer.catalog_scope_id = ap.catalog_scope_id and producer.producer_id = ap.producer_id and producer.enabled
                  join rbac3_catalog_permission_version pv on pv.catalog_scope_id = ap.catalog_scope_id and pv.producer_id = ap.producer_id
                       and pv.producer_version = ap.producer_version and pv.permission_id = p.id
                 where g.catalog_scope_id = :scope and ap.activation_version = :catalog and g.role_id in (:roles)
                   and g.status = 'ACTIVE' and g.valid_from <= :now and (g.valid_to is null or g.valid_to > :now)
                 order by permission_code
                """, Map.of("scope", scope, "catalog", catalog, "roles", roles.stream().map(Long::valueOf).toList(), "now", now))
                .stream().map(row -> text(row[0])).toList();
    }

    private Map<String, top.egon.cola.platform.tianquan.jianshen.contract.authorization.DataScopeDecision> dataScopes(
            long scope, long user, List<String> roles, List<String> permissions, long auth, long policy, String tenant, Instant now) {
        if (roles.isEmpty() || permissions.isEmpty()) return Map.of();
        Set<String> grantedPermissions = Set.copyOf(permissions);
        var values = new java.util.ArrayList<top.egon.cola.platform.tianquan.jianshen.core.activation.AuthorizationRuleFacts.DataScopeFact>();
        for (Object[] row : rows("""
                select d.role_id, p.permission_code, d.scope_type, r.ref_type, r.ref_id, coalesce(d.directory_snapshot_version,0)
                  from rbac3_data_rule d join rbac3_catalog_permission p on p.catalog_scope_id = d.catalog_scope_id and p.id = d.permission_id
                  left join rbac3_data_rule_ref r on r.tenant_id = d.tenant_id and r.data_rule_id = d.id
                 where d.catalog_scope_id = :scope and d.role_id in (:roles) and d.status = 'ACTIVE'
                   and d.valid_from <= :now and (d.valid_to is null or d.valid_to > :now)
                """, Map.of("scope", scope, "roles", roles.stream().map(Long::valueOf).toList(), "now", now))) {
            if (!grantedPermissions.contains(text(row[1]))) continue;
            String kind = text(row[2]);
            String dimension = "NONE"; String reference = null;
            if ("ALL".equals(kind)) dimension = "TENANT_ALL";
            else if ("SELF".equals(kind)) { dimension = "USER"; reference = Long.toString(user); }
            else if (row[3] != null && row[4] != null) {
                dimension = java.util.Set.of("ORG_TREE", "DEPT_TREE").contains(kind) ? kind : text(row[3]); reference = text(row[4]);
            }
            values.add(new top.egon.cola.platform.tianquan.jianshen.core.activation.AuthorizationRuleFacts.DataScopeFact(
                    text(row[0]), text(row[1]), dimension, reference, number(row[5])));
        }
        var merged = new top.egon.cola.platform.tianquan.jianshen.core.decision.DataScopeMerger().merge(values, Set.copyOf(roles));
        var result = new java.util.TreeMap<String, top.egon.cola.platform.tianquan.jianshen.contract.authorization.DataScopeDecision>();
        merged.forEach((code, value) -> {
            var refs = value.referencesByDimension();
            Set<String> orgs = references(refs, "ORG", "ORG_TREE");
            Set<String> departments = references(refs, "DEPT", "DEPT_TREE");
            Set<String> users = references(refs, "USER");
            boolean self = users.contains(Long.toString(user));
            boolean allowed = value.allInTenant() || !orgs.isEmpty() || !departments.isEmpty() || !users.isEmpty();
            result.put(code, new top.egon.cola.platform.tianquan.jianshen.contract.authorization.DataScopeDecision(
                    allowed ? top.egon.cola.platform.tianquan.jianshen.contract.authorization.Decision.ALLOW
                            : top.egon.cola.platform.tianquan.jianshen.contract.authorization.Decision.DENY,
                    allowed ? "ALLOW" : "DATA_SCOPE_MISSING", tenant, Long.toString(user), code,
                    !allowed ? "NONE" : value.allInTenant() ? "ALL" : self && refs.size() == 1 ? "SELF" : "CUSTOM",
                    value.allInTenant(), orgs, refs.containsKey("ORG_TREE"), departments, refs.containsKey("DEPT_TREE"), users,
                    self, self ? Long.toString(user) : null, Long.toString(value.directorySnapshotVersion()), policy,
                    auth, policy, List.of(), now));
        });
        return Map.copyOf(result);
    }

    private static Set<String> references(Map<String, Set<String>> values, String... dimensions) {
        var result = new java.util.TreeSet<String>();
        for (String dimension : dimensions) result.addAll(values.getOrDefault(dimension, Set.of()));
        return Set.copyOf(result);
    }

    private Set<String> resources(long scope, long catalog) {
        return rows("""
                select rv.registration_key from rbac3_catalog_activation_producer ap
                  join rbac3_catalog_producer producer on producer.catalog_scope_id = ap.catalog_scope_id and producer.producer_id = ap.producer_id and producer.enabled
                  join rbac3_catalog_resource_version rv on rv.catalog_scope_id = ap.catalog_scope_id and rv.producer_id = ap.producer_id
                       and rv.producer_version = ap.producer_version
                  join rbac3_catalog_resource r on r.catalog_scope_id = rv.catalog_scope_id and r.id = rv.resource_id
                 where ap.catalog_scope_id = :scope and ap.activation_version = :catalog and r.governance_state = 'ACTIVE'
                """, Map.of("scope", scope, "catalog", catalog)).stream().map(row -> text(row[0])).collect(java.util.stream.Collectors.toUnmodifiableSet());
    }

    private EffectivePermissionSnapshot publish(EffectivePermissionSnapshot view, long userId, Instant now) {
        // Replace a nearly expired head when this decision has a longer lifetime to publish.
        String renewalLead = properties.snapshotTtl().dividedBy(2).toMillis() + " milliseconds";
        List<Object[]> heads = rows("""
                select cast(s.snapshot_json as text), s.snapshot_digest from rbac3_catalog_snapshot_head h
                join rbac3_catalog_effective_snapshot s on s.id = h.snapshot_id
                where h.catalog_scope_id = :scope and h.user_id = :user and h.auth_version = :auth
                  and h.tenant_policy_version = :policy and h.catalog_version = :catalog and s.expires_at > clock_timestamp()
                  and (s.expires_at >= :newExpiry or s.expires_at > clock_timestamp() + cast(:renewalLead as interval))
                """, Map.of("scope", Long.parseLong(view.catalogScope().catalogScopeId()), "user", userId,
                "auth", Long.parseLong(view.authVersion()), "policy", Long.parseLong(view.policyVersion()),
                "catalog", Long.parseLong(view.catalogVersion()), "newExpiry", view.snapshotExpiresAt(), "renewalLead", renewalLead));
        if (heads.size() == 1) {
            try {
                Map<String, Object> encoded = mapper.readValue(text(heads.getFirst()[0]), Map.class);
                if (!CanonicalJson.digest(encoded).equals(text(heads.getFirst()[1]).trim())) {
                    throw new Rbac3RuleViolation("AUTH_RUNTIME_CHECKSUM_MISMATCH");
                }
                EffectivePermissionSnapshot existing = mapper.convertValue(encoded, EffectivePermissionSnapshot.class);
                if (existing.issuer().equals(view.issuer()) && existing.subject().equals(view.subject())
                        && existing.catalogScope().equals(view.catalogScope()) && existing.catalogVersion().equals(view.catalogVersion())
                        && existing.authVersion().equals(view.authVersion()) && existing.policyVersion().equals(view.policyVersion())
                        && existing.activeRoleContext().equals(view.activeRoleContext()) && existing.permissionCodes().equals(view.permissionCodes())) {
                    Instant bounded = existing.snapshotExpiresAt().isBefore(view.snapshotExpiresAt())
                            ? existing.snapshotExpiresAt() : view.snapshotExpiresAt();
                    return new EffectivePermissionSnapshot(view.issuer(), view.subject(), view.catalogScope(), view.catalogVersion(),
                            view.authVersion(), view.policyVersion(), view.activeRoleContext(), view.permissionCodes(), bounded);
                }
            } catch (com.fasterxml.jackson.core.JsonProcessingException invalid) {
                throw new Rbac3RuleViolation("AUTH_RUNTIME_PAYLOAD_INVALID");
            }
        }
        Map<String, Object> value = mapper.convertValue(view, Map.class);
        String json = CanonicalJson.write(value);
        String digest = CanonicalJson.digest(value);
        String roleDigest = CanonicalJson.digest(mapper.convertValue(view.activeRoleContext(), Map.class));
        long id = ids.getAsLong();
        Map<String, Object> parameters = Map.of("id", id, "scope", Long.parseLong(view.catalogScope().catalogScopeId()),
                "user", userId, "auth", Long.parseLong(view.authVersion()), "policy", Long.parseLong(view.policyVersion()),
                "catalog", Long.parseLong(view.catalogVersion()), "role", roleDigest, "now", now);
        var insert = entityManager.createNativeQuery("""
                insert into rbac3_catalog_effective_snapshot
                  (id, catalog_scope_id, tenant_id, user_id, issuer, subject, auth_version, tenant_policy_version,
                   catalog_version, role_context_digest, snapshot_digest, snapshot_json, expires_at, created_at)
                values (:id, :scope, :tenant, :user, :issuer, :subject, :auth, :policy, :catalog, :role,
                        :digest, cast(:json as jsonb), :expires, :now)
                """);
        parameters.forEach(insert::setParameter);
        insert.setParameter("tenant", Long.parseLong(view.catalogScope().tenantId())).setParameter("issuer", view.issuer())
                .setParameter("subject", view.subject()).setParameter("digest", digest).setParameter("json", json)
                .setParameter("expires", view.snapshotExpiresAt()).executeUpdate();
        var head = entityManager.createNativeQuery("""
                insert into rbac3_catalog_snapshot_head
                  (catalog_scope_id, user_id, snapshot_id, auth_version, tenant_policy_version, catalog_version,
                   role_context_digest, fence_version, version, updated_at)
                values (:scope, :user, :id, :auth, :policy, :catalog, :role, 0, 0, :now)
                on conflict (catalog_scope_id, user_id) do update set snapshot_id = excluded.snapshot_id,
                  auth_version = excluded.auth_version, tenant_policy_version = excluded.tenant_policy_version,
                  catalog_version = excluded.catalog_version, role_context_digest = excluded.role_context_digest,
                  fence_version = rbac3_catalog_snapshot_head.fence_version + 1,
                  version = rbac3_catalog_snapshot_head.version + 1, updated_at = excluded.updated_at
                where rbac3_catalog_snapshot_head.auth_version <= excluded.auth_version
                  and rbac3_catalog_snapshot_head.tenant_policy_version <= excluded.tenant_policy_version
                  and rbac3_catalog_snapshot_head.catalog_version <= excluded.catalog_version
                """);
        parameters.forEach(head::setParameter);
        if (head.executeUpdate() != 1) throw new Rbac3RuleViolation("AUTH_RUNTIME_VERSION_CONFLICT");
        return view;
    }

    private Object[] one(String sql, Map<String, ?> parameters, String reason) {
        List<Object[]> values = rows(sql, parameters);
        if (values.size() != 1) throw new Rbac3RuleViolation(reason);
        return values.getFirst();
    }

    private List<Object[]> rows(String sql, Map<String, ?> parameters) {
        var query = entityManager.createNativeQuery(sql);
        parameters.forEach(query::setParameter);
        List<?> values = query.getResultList();
        return values.stream().map(value -> value instanceof Object[] row ? row : new Object[]{value}).toList();
    }

    private static Instant instant(Object value) {
        if (value instanceof Instant instant) return instant;
        if (value instanceof java.time.OffsetDateTime offset) return offset.toInstant();
        return ((java.sql.Timestamp) value).toInstant();
    }

    private static String text(Object value) { return value.toString(); }
    private static long number(Object value) { return ((Number) value).longValue(); }
}
