package top.egon.cola.platform.tianquan.jianshen.admin.bootstrap.repository;

import jakarta.persistence.EntityManager;
import jakarta.persistence.LockModeType;
import jakarta.persistence.Query;
import org.springframework.transaction.annotation.Propagation;
import org.springframework.transaction.annotation.Transactional;
import top.egon.cola.component.common.id.snowflake.SnowflakeIdGenerator;
import top.egon.cola.platform.tianquan.jianshen.admin.authorization.grant.application.domain.enums.TenantApplicationStatusEnum;
import top.egon.cola.platform.tianquan.jianshen.admin.authorization.grant.application.domain.po.TenantApplicationPO;
import top.egon.cola.platform.tianquan.jianshen.admin.authorization.grant.business.domain.po.UserBusinessAccessPO;
import top.egon.cola.platform.tianquan.jianshen.admin.authorization.grant.userrole.domain.enums.UserRoleAssignmentTypeEnum;
import top.egon.cola.platform.tianquan.jianshen.admin.authorization.grant.userrole.domain.po.UserRoleAssignmentPO;
import top.egon.cola.platform.tianquan.jianshen.admin.authorization.runtime.activation.domain.po.UserActiveRolePO;
import top.egon.cola.platform.tianquan.jianshen.admin.bootstrap.domain.dto.PermissionAdministratorBootstrapCommandDTO;
import top.egon.cola.platform.tianquan.jianshen.admin.bootstrap.domain.dto.PermissionCatalogBootstrapCommandDTO;
import top.egon.cola.platform.tianquan.jianshen.admin.bootstrap.domain.vo.PermissionBootstrapReceiptVO;
import top.egon.cola.platform.tianquan.jianshen.admin.iam.role.domain.enums.RoleRiskLevelEnum;
import top.egon.cola.platform.tianquan.jianshen.admin.iam.role.domain.enums.RoleTypeEnum;
import top.egon.cola.platform.tianquan.jianshen.admin.iam.role.domain.po.RolePO;
import top.egon.cola.platform.tianquan.jianshen.admin.iam.user.domain.enums.UserStatusEnum;
import top.egon.cola.platform.tianquan.jianshen.admin.iam.user.domain.po.UserPO;
import top.egon.cola.platform.tianquan.jianshen.admin.registration.catalog.domain.convertor.PermissionCatalogJson;
import top.egon.cola.platform.tianquan.jianshen.admin.registration.catalog.repository.PermissionCatalogScopeRepository;
import top.egon.cola.platform.tianquan.jianshen.contract.permission.CanonicalJson;
import top.egon.cola.platform.tianquan.jianshen.contract.permission.CatalogScope;

import java.time.Instant;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Optional;
import java.util.regex.Pattern;

/** Persistence for explicit operator initialization; ordinary application startup never calls this repository. */
@Transactional(propagation = Propagation.MANDATORY)
public class PermissionBootstrapRepository {
    public static final String ACTOR = "permission-catalog-bootstrap";
    public record Administrator(long userId, long roleId, long assignmentId, long authVersion) { }
    public record ApplicationBinding(long applicationId, String businessId, String applicationPublicId) { }

    private final EntityManager entityManager;
    private final PermissionCatalogJson json;

    public PermissionBootstrapRepository(EntityManager entityManager, PermissionCatalogJson json) {
        this.entityManager = entityManager;
        this.json = json;
    }

    public void lockTenant(String tenantId) {
        query("select pg_advisory_xact_lock(:namespace, :tenant)",
                Map.of("namespace", 0x50414342, "tenant", Long.hashCode(Long.parseLong(tenantId)))).getSingleResult();
    }

    public Optional<PermissionBootstrapReceiptVO> original(String tenantId, String operationId, String digest) {
        List<?> rows = query("""
                select after_snapshot->>'commandDigest', cast(after_snapshot->'receipt' as text)
                  from rbac3_audit_log
                 where tenant_id=:tenant and request_id=:operation
                   and event_type in ('PERMISSION_CATALOG_BOOTSTRAPPED','PERMISSION_ADMIN_BOOTSTRAPPED')
                """, Map.of("tenant", Long.parseLong(tenantId), "operation", operationId)).getResultList();
        if (rows.isEmpty()) return Optional.empty();
        if (rows.size() != 1) throw new IllegalStateException("BOOTSTRAP_RECEIPT_AMBIGUOUS");
        Object[] row = (Object[]) rows.getFirst();
        if (!digest.equals(row[0])) throw new IllegalStateException("BOOTSTRAP_OPERATION_CONFLICT");
        var receipt = json.read(row[1].toString(), PermissionBootstrapReceiptVO.class);
        if (!operationId.equals(receipt.operationId()) || !digest.equals(receipt.commandDigest())) {
            throw new IllegalStateException("BOOTSTRAP_RECEIPT_MISMATCH");
        }
        return Optional.of(receipt);
    }

    public void requireAdministratorNotInitialized(CatalogScope target) {
        Number count = (Number) query("""
                select count(*) from rbac3_audit_log where tenant_id=:tenant
                   and event_type='PERMISSION_ADMIN_BOOTSTRAPPED' and target_type='CATALOG_SCOPE' and target_id=:scope
                """, Map.of("tenant", Long.parseLong(target.tenantId()), "scope", target.catalogScopeId())).getSingleResult();
        if (count.longValue() != 0) throw new IllegalStateException("BOOTSTRAP_ADMIN_ALREADY_INITIALIZED");
    }

    public Map<String, String> initializeCatalog(PermissionCatalogBootstrapCommandDTO command, Instant now) {
        Map<String, Object> values = base(command.target(), now);
        values.put("application", Long.parseLong(command.applicationId()));
        values.put("name", command.applicationName());
        values.put("businessPublic", command.ddcBusinessId());
        values.put("applicationPublic", command.ddcApplicationId());
        // This explicit database-owner seed is deliberately separate from the HTTP verified-membership marker.
        query("""
                insert into rbac3_tenant_authorization_state(tenant_id,created_at,created_by,updated_at,updated_by)
                values(:tenant,:now,:actor,:now,:actor) on conflict(tenant_id) do nothing
                """, values).executeUpdate();
        List<?> applications = query("""
                select id,application_code,ddc_business_id,ddc_application_id,status from rbac3_application
                 where id=:application or application_code=:applicationCode for update
                """, values).getResultList();
        if (applications.isEmpty()) {
            query("""
                    insert into rbac3_application(id,application_code,application_name,display_priority,status,version,
                            created_at,created_by,updated_at,updated_by,ddc_application_id,ddc_business_id)
                    values(:application,:applicationCode,:name,0,'ACTIVE',0,:now,:actor,:now,:actor,:applicationPublic,:businessPublic)
                    """, values).executeUpdate();
        } else {
            if (applications.size() != 1) throw new IllegalStateException("BOOTSTRAP_APPLICATION_CONFLICT");
            Object[] row = (Object[]) applications.getFirst();
            if (!command.applicationId().equals(row[0].toString()) || !command.target().applicationCode().equals(row[1])
                    || !command.ddcBusinessId().equals(row[2]) || !command.ddcApplicationId().equals(row[3]) || !"ACTIVE".equals(row[4])) {
                throw new IllegalStateException("BOOTSTRAP_APPLICATION_CONFLICT");
            }
        }
        List<?> scopes = query("""
                select tenant_id,business_code,application_id,application_code,namespace_code,environment,ddc_business_id,ddc_application_id,status
                  from rbac3_catalog_scope where id=:scope for update
                """, values).getResultList();
        if (scopes.isEmpty()) {
            query("""
                    insert into rbac3_catalog_scope(id,tenant_id,business_code,application_id,application_code,namespace_code,environment,
                            ddc_business_id,ddc_application_id,status,created_at,created_by,updated_at,updated_by)
                    values(:scope,:tenant,:business,:application,:applicationCode,:namespace,:environment,:businessPublic,:applicationPublic,
                            'ACTIVE',:now,:actor,:now,:actor)
                    """, values).executeUpdate();
        } else {
            Object[] row = (Object[]) scopes.getFirst();
            if (!List.of(command.target().tenantId(), command.target().businessCode(), command.applicationId(), command.target().applicationCode(),
                    command.target().namespaceCode(), command.target().environment(), command.ddcBusinessId(), command.ddcApplicationId(), "ACTIVE")
                    .equals(java.util.Arrays.stream(row).map(Object::toString).toList())) throw new IllegalStateException("BOOTSTRAP_SCOPE_CONFLICT");
        }
        query("""
                insert into rbac3_catalog_active_pointer(catalog_scope_id,updated_at,updated_by)
                values(:scope,:now,:actor) on conflict(catalog_scope_id) do nothing
                """, values).executeUpdate();
        Number revision = (Number) query("select revision from rbac3_catalog_active_pointer where catalog_scope_id=:scope for update", values).getSingleResult();
        if (revision.longValue() != 0) throw new IllegalStateException("BOOTSTRAP_CATALOG_ALREADY_ACTIVE");
        Map<String, String> facts = new LinkedHashMap<>();
        for (var producer : command.producers()) {
            ensureProducer(command.target(), producer, now);
            for (var grant : producer.serviceGrants()) {
                facts.put(producer.producerId() + "/grant/" + grant.bindingDigest(), Long.toString(ensureGrant(command.target(), producer.producerId(), grant, now)));
            }
        }
        return Map.copyOf(facts);
    }

    private void ensureProducer(CatalogScope target, PermissionCatalogBootstrapCommandDTO.Producer producer, Instant now) {
        Map<String, Object> values = base(target, now);
        values.put("producer", producer.producerId());
        values.put("kind", producer.kind().name());
        values.put("keys", CanonicalJson.write(producer.ownedKeyPrefixes()));
        values.put("permissions", CanonicalJson.write(producer.ownedPermissionPrefixes()));
        values.put("messages", CanonicalJson.write(producer.ownedMessagePrefixes()));
        values.put("modules", CanonicalJson.write(producer.expectedModules()));
        List<?> owners = query("""
                select producer_id,kind,cast(owned_key_prefixes as text),cast(owned_permission_prefixes as text),
                       cast(owned_message_prefixes as text),cast(expected_modules as text),current_revision,enabled,version
                  from rbac3_catalog_producer where catalog_scope_id=:scope order by producer_id for update
                """, values).getResultList();
        boolean existing = false;
        for (Object item : owners) {
            Object[] owner = (Object[]) item;
            if (producer.producerId().equals(owner[0])) {
                if (!producer.kind().name().equals(owner[1]) || !producer.ownedKeyPrefixes().equals(json.strings(owner[2].toString()))
                        || !producer.ownedPermissionPrefixes().equals(json.strings(owner[3].toString()))
                        || !producer.ownedMessagePrefixes().equals(json.strings(owner[4].toString()))
                        || !producer.expectedModules().equals(json.strings(owner[5].toString()))
                        || ((Number) owner[6]).longValue() != 0 || !Boolean.TRUE.equals(owner[7]) || ((Number) owner[8]).longValue() != 0) {
                    throw new IllegalStateException("BOOTSTRAP_PRODUCER_CONFLICT");
                }
                existing = true;
                continue;
            }
            if (producer.producerId().equalsIgnoreCase(owner[0].toString())
                    || overlaps(producer.ownedKeyPrefixes(), json.strings(owner[2].toString()))
                    || overlaps(producer.ownedPermissionPrefixes(), json.strings(owner[3].toString()))
                    || overlaps(producer.ownedMessagePrefixes(), json.strings(owner[4].toString()))) {
                throw new IllegalStateException("BOOTSTRAP_OWNER_PREFIX_CONFLICT");
            }
        }
        if (existing) return;
        query("""
                insert into rbac3_catalog_producer(catalog_scope_id,producer_id,kind,owned_key_prefixes,owned_permission_prefixes,
                        owned_message_prefixes,expected_modules,enabled,created_at,created_by,updated_at,updated_by)
                values(:scope,:producer,:kind,cast(:keys as jsonb),cast(:permissions as jsonb),cast(:messages as jsonb),cast(:modules as jsonb),
                        true,:now,:actor,:now,:actor)
                """, values).executeUpdate();
    }

    private long ensureGrant(CatalogScope target, String producer, PermissionCatalogBootstrapCommandDTO.ServiceGrant grant, Instant now) {
        Map<String, Object> values = base(target, now);
        values.put("producer", producer); values.put("digest", grant.bindingDigest()); values.put("issuer", grant.issuer().toString());
        values.put("client", grant.clientId()); values.put("resource", grant.resourceUri().toString());
        List<String> capabilities = grant.capabilities().stream().map(Enum::name).sorted().toList();
        values.put("capabilities", CanonicalJson.write(capabilities)); values.put("refs", CanonicalJson.write(grant.allowedSourceRefs()));
        values.put("expansion", grant.allowPermissionExpansion());
        List<?> rows = query("""
                select id,issuer,client_id,resource_uri,cast(capabilities as text),cast(allowed_source_refs as text),
                       allow_permission_expansion,enabled,version from rbac3_catalog_service_grant
                 where catalog_scope_id=:scope and producer_id=:producer and principal_binding_digest=:digest for update
                """, values).getResultList();
        if (!rows.isEmpty()) {
            Object[] row = (Object[]) rows.getFirst();
            if (!grant.issuer().toString().equals(row[1]) || !grant.clientId().equals(row[2]) || !grant.resourceUri().toString().equals(row[3])
                    || !capabilities.equals(json.strings(row[4].toString()).stream().sorted().toList())
                    || !grant.allowedSourceRefs().equals(json.strings(row[5].toString())) || !Boolean.valueOf(grant.allowPermissionExpansion()).equals(row[6])
                    || !Boolean.TRUE.equals(row[7]) || ((Number) row[8]).longValue() != 0) throw new IllegalStateException("BOOTSTRAP_SERVICE_GRANT_CONFLICT");
            return ((Number) row[0]).longValue();
        }
        long id = SnowflakeIdGenerator.nextLongId(); values.put("id", id);
        query("""
                insert into rbac3_catalog_service_grant(id,catalog_scope_id,producer_id,issuer,client_id,resource_uri,principal_binding_digest,
                        capabilities,allowed_source_refs,allow_permission_expansion,enabled,created_at,created_by,updated_at,updated_by)
                values(:id,:scope,:producer,:issuer,:client,:resource,:digest,cast(:capabilities as jsonb),cast(:refs as jsonb),:expansion,
                        true,:now,:actor,:now,:actor)
                """, values).executeUpdate();
        return id;
    }

    public ApplicationBinding application(CatalogScope target) {
        Object[] row = (Object[]) query("select application_id,ddc_business_id,ddc_application_id from rbac3_catalog_scope where id=:scope and tenant_id=:tenant",
                Map.of("scope", Long.parseLong(target.catalogScopeId()), "tenant", Long.parseLong(target.tenantId()))).getSingleResult();
        return new ApplicationBinding(((Number) row[0]).longValue(), row[1].toString(), row[2].toString());
    }

    public void requireQualifiedActiveCatalog(PermissionCatalogScopeRepository.ScopeState scope) {
        List<?> rows = query("""
                select a.producer_count, (select count(*) from rbac3_catalog_activation_producer member
                    join rbac3_catalog_producer owner on owner.catalog_scope_id=member.catalog_scope_id
                         and owner.producer_id=member.producer_id and owner.enabled
                    join rbac3_catalog_manifest manifest on manifest.catalog_scope_id=member.catalog_scope_id
                         and manifest.producer_id=member.producer_id and manifest.producer_version=member.producer_version
                         and manifest.state='READY' and manifest.manifest_digest=member.manifest_digest
                         and manifest.policy_digest=member.policy_digest and manifest.metadata_digest=member.metadata_digest
                    join rbac3_catalog_deployment_qualification proof on proof.catalog_scope_id=member.catalog_scope_id
                         and proof.producer_id=member.producer_id and proof.producer_version=member.producer_version
                         and proof.id=member.qualification_id and proof.manifest_digest=member.manifest_digest
                         and proof.policy_digest=member.policy_digest and proof.commit=manifest.commit and proof.build_id=manifest.build_id
                    where member.catalog_scope_id=a.catalog_scope_id and member.activation_version=a.activation_version
                         and proof.verified_at<=a.created_at and proof.expires_at>a.created_at)
                  from rbac3_catalog_active_pointer head join rbac3_catalog_activation a
                    on a.catalog_scope_id=head.catalog_scope_id and a.activation_version=head.activation_version
                 where head.catalog_scope_id=:scope and head.revision=:revision
                """, Map.of("scope", Long.parseLong(scope.scope().catalogScopeId()), "revision", scope.activeRevision())).getResultList();
        // Qualifications are admission evidence at activation time, matching the ordinary runtime binding check.
        if (rows.size() != 1) throw new IllegalStateException("BOOTSTRAP_ACTIVE_QUALIFICATION_MISSING");
        Object[] row = (Object[]) rows.getFirst();
        long expected = ((Number) row[0]).longValue();
        if (expected <= 0 || expected != ((Number) row[1]).longValue()) throw new IllegalStateException("BOOTSTRAP_ACTIVE_QUALIFICATION_MISSING");
    }

    public Administrator initializeAdministrator(PermissionCatalogScopeRepository.ScopeState scope,
            PermissionAdministratorBootstrapCommandDTO command, Instant from, Instant now) {
        Long tenant = Long.parseLong(command.target().tenantId()); Long application = scope.applicationId();
        List<?> roles = query("select id from rbac3_role where tenant_id=:tenant and application_id=:application and role_code=:code for update",
                Map.of("tenant", tenant, "application", application, "code", command.roleCode())).getResultList();
        if (!roles.isEmpty()) throw new IllegalStateException("BOOTSTRAP_ROLE_ALREADY_EXISTS");
        List<UserPO> users = entityManager.createQuery("select u from UserEntity u where u.tenantId=:tenant and u.identitySub=:subject", UserPO.class)
                .setParameter("tenant", tenant).setParameter("subject", command.identitySub()).setLockMode(LockModeType.PESSIMISTIC_WRITE).getResultList();
        if (users.size() > 1) throw new IllegalStateException("BOOTSTRAP_USER_CONFLICT");
        UserPO user = users.isEmpty() ? new UserPO(SnowflakeIdGenerator.nextLongId(), tenant, command.identitySub(), UserStatusEnum.ACTIVE, ACTOR, now) : users.getFirst();
        if (user.getStatus() != UserStatusEnum.ACTIVE) throw new IllegalStateException("BOOTSTRAP_USER_DISABLED");
        if (users.isEmpty()) entityManager.persist(user);
        var binding = application(command.target());
        ensureTenantApplication(tenant, application, command.operationId(), from, command.validTo(), now);
        ensureBusinessAccess(tenant, user.getId(), binding.businessId(), command.operationId(), from, command.validTo(), now);
        if (command.activateRole()) {
            Number active = (Number) query("select count(*) from rbac3_user_active_role where tenant_id=:tenant and user_id=:user and application_id=:application",
                    Map.of("tenant", tenant, "user", user.getId(), "application", application)).getSingleResult();
            if (active.longValue() != 0) throw new IllegalStateException("BOOTSTRAP_ACTIVE_ROLE_ALREADY_EXISTS");
        }
        long roleId = SnowflakeIdGenerator.nextLongId(); long assignmentId = SnowflakeIdGenerator.nextLongId();
        entityManager.persist(new RolePO(roleId, tenant, application, command.roleCode(), command.roleName(), RoleTypeEnum.MANAGEMENT,
                RoleRiskLevelEnum.CRITICAL, true, null, 0, null, ACTOR, now));
        entityManager.flush();
        query("insert into rbac3_role_closure(tenant_id,application_id,ancestor_role_id,descendant_role_id,depth) values(:tenant,:application,:role,:role,0)",
                Map.of("tenant", tenant, "application", application, "role", roleId)).executeUpdate();
        entityManager.persist(new UserRoleAssignmentPO(assignmentId, tenant, user.getId(), roleId, UserRoleAssignmentTypeEnum.DIRECT,
                from, command.validTo(), "BOOTSTRAP", command.operationId(), "Explicit initial permission administrator", null, ACTOR, now));
        // The role is new, has no inheritance or constraints, and has exactly this direct assignment as activation evidence.
        if (command.activateRole()) entityManager.persist(new UserActiveRolePO(tenant, user.getId(), application, roleId, List.of(Long.toString(assignmentId)), now));
        long version = user.incrementAuthVersion(ACTOR, now);
        entityManager.flush();
        return new Administrator(user.getId(), roleId, assignmentId, version);
    }

    private void ensureTenantApplication(Long tenant, Long application, String operation, Instant from, Instant until, Instant now) {
        List<TenantApplicationPO> rows = entityManager.createQuery("select a from TenantApplicationEntity a where a.tenantId=:tenant and a.applicationId=:application", TenantApplicationPO.class)
                .setParameter("tenant", tenant).setParameter("application", application).setLockMode(LockModeType.PESSIMISTIC_WRITE).getResultList();
        if (rows.isEmpty()) entityManager.persist(new TenantApplicationPO(SnowflakeIdGenerator.nextLongId(), tenant, application,
                TenantApplicationStatusEnum.ACTIVE, from, until, "SYSTEM", operation, "Explicit catalog administrator bootstrap", null, ACTOR, now));
        else if (rows.size() != 1 || !rows.getFirst().isEffectiveAt(now)) throw new IllegalStateException("BOOTSTRAP_APPLICATION_ENTITLEMENT_CONFLICT");
    }

    private void ensureBusinessAccess(Long tenant, Long user, String business, String operation, Instant from, Instant until, Instant now) {
        List<UserBusinessAccessPO> rows = entityManager.createQuery("select a from UserBusinessAccessEntity a where a.tenantId=:tenant and a.userId=:user and a.ddcBusinessId=:business", UserBusinessAccessPO.class)
                .setParameter("tenant", tenant).setParameter("user", user).setParameter("business", business).setLockMode(LockModeType.PESSIMISTIC_WRITE).getResultList();
        if (rows.isEmpty()) entityManager.persist(new UserBusinessAccessPO(SnowflakeIdGenerator.nextLongId(), tenant, user, business,
                from, until, "SYSTEM", operation, "Explicit catalog administrator bootstrap", null, ACTOR, now));
        else if (rows.stream().noneMatch(row -> row.isEffective(now))) throw new IllegalStateException("BOOTSTRAP_BUSINESS_ENTITLEMENT_CONFLICT");
    }

    public List<String> producerIds(CatalogScope target) {
        return query("select producer_id from rbac3_catalog_producer where catalog_scope_id=:scope order by producer_id",
                Map.of("scope", Long.parseLong(target.catalogScopeId()))).getResultList().stream().map(Object::toString).toList();
    }

    private Map<String, Object> base(CatalogScope target, Instant now) {
        Map<String, Object> values = new LinkedHashMap<>();
        values.put("scope", Long.parseLong(target.catalogScopeId())); values.put("tenant", Long.parseLong(target.tenantId()));
        values.put("business", target.businessCode()); values.put("applicationCode", target.applicationCode());
        values.put("namespace", target.namespaceCode()); values.put("environment", target.environment()); values.put("now", now); values.put("actor", ACTOR);
        return values;
    }

    private boolean overlaps(List<String> first, List<String> second) {
        return first.stream().map(value -> value.toLowerCase(java.util.Locale.ROOT))
                .anyMatch(left -> second.stream().map(value -> value.toLowerCase(java.util.Locale.ROOT))
                        .anyMatch(right -> left.startsWith(right) || right.startsWith(left)));
    }

    private Query query(String sql, Map<String, Object> values) {
        Query query = entityManager.createNativeQuery(sql);
        values.forEach((key, value) -> { if (Pattern.compile(":" + Pattern.quote(key) + "\\b").matcher(sql).find()) query.setParameter(key, value); });
        return query;
    }
}
