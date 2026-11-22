package top.egon.cola.platform.tianquan.jianshen.admin.authorization.runtime.catalog;

import top.egon.cola.platform.tianquan.jianshen.admin.registration.catalog.repository.CatalogAdministrationGuard;

import top.egon.cola.platform.tianquan.jianshen.admin.registration.catalog.domain.convertor.PermissionCatalogJson;
import top.egon.cola.platform.tianquan.jianshen.admin.registration.catalog.domain.vo.DeploymentQualificationReceiptVO;
import top.egon.cola.platform.tianquan.jianshen.admin.registration.catalog.service.*;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.datatype.jsr310.JavaTimeModule;
import jakarta.persistence.EntityManager;
import org.flywaydb.core.Flyway;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.springframework.jdbc.datasource.DriverManagerDataSource;
import org.springframework.orm.jpa.LocalContainerEntityManagerFactoryBean;
import org.springframework.orm.jpa.vendor.HibernateJpaVendorAdapter;
import top.egon.cola.platform.tianquan.jianshen.admin.audit.service.AuditQueryService;
import top.egon.cola.platform.tianquan.jianshen.admin.authorization.runtime.repository.AuthorizationEventPublisher;
import top.egon.cola.platform.tianquan.jianshen.admin.authorization.runtime.state.repository.jpa.JpaTenantAuthorizationStateRepository;
import top.egon.cola.platform.tianquan.jianshen.admin.registration.catalog.domain.PermissionCatalogCaller;
import top.egon.cola.platform.tianquan.jianshen.admin.registration.catalog.repository.DeploymentQualificationRepository;
import top.egon.cola.platform.tianquan.jianshen.admin.registration.catalog.repository.PermissionCatalogActivationRepository;
import top.egon.cola.platform.tianquan.jianshen.admin.registration.catalog.repository.PermissionCatalogDefinitionRepository;
import top.egon.cola.platform.tianquan.jianshen.admin.registration.catalog.repository.PermissionCatalogScopeRepository;
import top.egon.cola.platform.tianquan.jianshen.admin.registration.catalog.repository.PermissionManifestRepository;
import top.egon.cola.platform.tianquan.jianshen.admin.registration.catalog.repository.PermissionSourceOutboxRepository;
import top.egon.cola.platform.tianquan.jianshen.contract.permission.CatalogActivationRequest;
import top.egon.cola.platform.tianquan.jianshen.contract.permission.DeploymentQualificationRequest;
import top.egon.cola.platform.tianquan.jianshen.contract.permission.ManifestRegistrationRequest;
import top.egon.cola.platform.tianquan.jianshen.contract.permission.SourceImportReceipt;
import top.egon.cola.platform.tianquan.jianshen.contract.permission.SourceImportRequest;
import top.egon.cola.platform.tianquan.jianshen.core.rule.Rbac3RuleViolation;
import top.egon.cola.platform.tianquan.jianshen.admin.shared.tenant.domain.CatalogProjectionTenantContext;
import org.springframework.security.core.context.SecurityContextHolder;
import top.egon.cola.platform.tianquan.shoubing.contract.ServiceIdentityPrincipal;

import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.sql.DriverManager;
import java.util.Arrays;
import java.util.List;
import java.util.Map;
import java.util.Properties;
import java.util.UUID;
import java.util.concurrent.atomic.AtomicLong;
import java.util.function.Supplier;
import java.util.stream.Collectors;

import static org.junit.jupiter.api.Assertions.*;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.*;
import static top.egon.cola.platform.tianquan.jianshen.admin.authorization.runtime.catalog.RuntimeCatalogPostgresqlFixture.*;

/** Explicit PostgreSQL-only profile. Creates and drops only an owned random schema; never starts an external process. */
class AuthorizationRuntimePostgresqlIT {
    private String url;
    private String user;
    private String password;
    private String schema;
    private boolean schemaCreated;
    private LocalContainerEntityManagerFactoryBean factory;
    private EntityManager entityManager;
    private PermissionCatalogJson json;
    private PermissionCatalogScopeRepository scopes;
    private PermissionManifestRepository manifests;
    private PermissionCatalogActivationRepository activations;
    private DeploymentQualificationRepository qualifications;
    private PermissionManifestPlanService plans;
    private PermissionManifestRegistrationService registrations;
    private PermissionSourceReceiptService receipts;
    private DeploymentQualificationService deployment;
    private PermissionCatalogActivationService catalogs;
    private PermissionCatalogCaller authority;
    private final AuditQueryService audit = mock(AuditQueryService.class);
    private final AtomicLong ids = new AtomicLong(100);
    private final List<String> recordedSql = new java.util.concurrent.CopyOnWriteArrayList<>();
    private boolean failFactLoad;

    @BeforeEach
    void connectToExplicitExistingDatabase() throws Exception {
        top.egon.cola.component.common.id.snowflake.SnowflakeIdGenerator.initialize(0L,
                top.egon.cola.component.common.id.snowflake.SnowflakeIdGenerator.DEFAULT_MAX_CLOCK_BACKWARD);
        url = environment("TIANQUAN_JIANSHEN_IT_POSTGRES_URL");
        user = environment("TIANQUAN_JIANSHEN_IT_POSTGRES_USER");
        password = Files.readString(Path.of(environment("TIANQUAN_JIANSHEN_IT_POSTGRES_PASSWORD_FILE")), StandardCharsets.UTF_8).strip();
        if (!url.startsWith("jdbc:postgresql:") || url.matches("(?is).*[?&](?:password|user)=.*")) {
            throw new IllegalArgumentException("the test URL must be PostgreSQL and must not embed credentials");
        }
        schema = "rbac3_it_" + UUID.randomUUID().toString().replace("-", "");
        try (var connection = DriverManager.getConnection(url, user, password); var statement = connection.createStatement()) {
            statement.execute("create schema " + schema);
            schemaCreated = true;
        }
        var flyway = Flyway.configure().dataSource(url, user, password).defaultSchema(schema).schemas(schema)
                .table("flyway_schema_history_rbac3").locations("classpath:db/migration")
                .initSql("SET rbac3.bootstrap.tenant_ids = '10'; SET rbac3.bootstrap.identity_sub = '9001'").load();
        flyway.migrate();
        assertTrue(flyway.validateWithResult().validationSuccessful);
        assertEquals("19", flyway.info().current().getVersion().getVersion());
        var dataSource = new DriverManagerDataSource(url, user, password);
        var properties = new Properties();
        properties.setProperty("currentSchema", schema);
        dataSource.setConnectionProperties(properties);
        factory = new LocalContainerEntityManagerFactoryBean();
        factory.setDataSource(dataSource);
        factory.setJpaVendorAdapter(new HibernateJpaVendorAdapter());
        factory.setPackagesToScan("top.egon.cola.platform.tianquan.jianshen.admin.authorization.runtime.state.domain.po");
        factory.setJpaPropertyMap(Map.of("hibernate.hbm2ddl.auto", "none", "hibernate.default_schema", schema,
                "hibernate.show_sql", false, "hibernate.session_factory.statement_inspector",
                (org.hibernate.resource.jdbc.spi.StatementInspector) sql -> { recordedSql.add(sql); return sql; }));
        factory.afterPropertiesSet();
        entityManager = factory.getObject().createEntityManager();
        json = new PermissionCatalogJson(new ObjectMapper().registerModule(new JavaTimeModule()));
        scopes = new PermissionCatalogScopeRepository(entityManager, json);
        manifests = new PermissionManifestRepository(entityManager, json);
        activations = new PermissionCatalogActivationRepository(entityManager, json);
        qualifications = new DeploymentQualificationRepository(entityManager, json);
        var definitions = new PermissionCatalogDefinitionRepository(entityManager);
        var events = mock(AuthorizationEventPublisher.class);
        plans = new PermissionManifestPlanService(scopes, definitions, manifests, audit, () -> NOW);
        registrations = new PermissionManifestRegistrationService(scopes, definitions, manifests, events, audit, () -> NOW, mock(PermissionSourceOutboxRepository.class));
        receipts = new PermissionSourceReceiptService(scopes, manifests, audit, () -> NOW, mock(PermissionSourceOutboxRepository.class));
        deployment = new DeploymentQualificationService(scopes, manifests, qualifications, json, audit, () -> NOW);
        catalogs = new PermissionCatalogActivationService(scopes, manifests, qualifications, activations,
                new JpaTenantAuthorizationStateRepository(entityManager, () -> NOW), events, audit, () -> NOW, mock(CatalogAdministrationGuard.class));
        var principal = caller().principal();
        authority = new PermissionCatalogCaller(caller().issuer(), new ServiceIdentityPrincipal(principal.subject(), principal.tenantId(), principal.clientId(),
                principal.tokenId(), principal.resourceUri(), principal.resourceVersion(), Arrays.stream(PermissionCatalogCaller.Capability.values())
                .map(PermissionCatalogCaller.Capability::scope).collect(Collectors.toSet()), principal.sourceBizCode(), principal.sourceAppCode(), principal.sourceEnvironment(),
                principal.credentialId(), principal.issuedAt(), principal.expiresAt(), principal.appId(), principal.scopeContext()));
        transaction(() -> {
            entityManager.createNativeQuery("""
                    insert into rbac3_application(id,application_code,application_name,display_priority,status,version,created_at,created_by,updated_at,updated_by,ddc_application_id,ddc_business_id)
                    values(20,'app','Catalog test',0,'ACTIVE',0,current_timestamp,'test',current_timestamp,'test','app','biz')
                    """).executeUpdate();
            entityManager.createNativeQuery("""
                    insert into rbac3_catalog_scope(id,tenant_id,business_code,application_id,application_code,namespace_code,environment,ddc_business_id,ddc_application_id,status,created_at,created_by,updated_at,updated_by)
                    values(1,10,'biz',20,'app','default','test','biz','app','ACTIVE',current_timestamp,'test',current_timestamp,'test')
                    """).executeUpdate();
            entityManager.createNativeQuery("""
                    insert into rbac3_catalog_producer(catalog_scope_id,producer_id,kind,owned_key_prefixes,owned_permission_prefixes,owned_message_prefixes,expected_modules,enabled,created_at,created_by,updated_at,updated_by)
                    values(1,'api','JAVA','["app."]','["app."]','["app/"]','["api"]',true,current_timestamp,'test',current_timestamp,'test')
                    """).executeUpdate();
            entityManager.createNativeQuery("""
                    insert into rbac3_catalog_active_pointer(catalog_scope_id,updated_at,updated_by) values(1,current_timestamp,'test')
                    """).executeUpdate();
            entityManager.createNativeQuery("""
                    insert into rbac3_catalog_service_grant(id,catalog_scope_id,producer_id,issuer,client_id,resource_uri,principal_binding_digest,capabilities,allowed_source_refs,allow_permission_expansion,enabled,created_at,created_by,updated_at,updated_by)
                    values(30,1,'api',:issuer,:client,:resource,:digest,'["REGISTER","ACTIVATE","READ_DESCRIPTOR","QUALIFY_DEPLOYMENT","CLEAR_PRODUCER"]','["refs/heads/main"]',true,true,current_timestamp,'test',current_timestamp,'test')
                    """).setParameter("issuer", authority.issuer().toString()).setParameter("client", authority.principal().clientId())
                    .setParameter("resource", authority.principal().resourceUri().toString()).setParameter("digest", authority.bindingDigest()).executeUpdate();
            return null;
        });
    }

    @AfterEach
    void closeOwnedSchema() throws Exception {
        if (entityManager != null) {
            if (entityManager.getTransaction().isActive()) entityManager.getTransaction().rollback();
            entityManager.close();
        }
        if (factory != null) factory.destroy();
        if (schemaCreated && schema != null && schema.matches("rbac3_it_[a-f0-9]{32}")) {
            try (var connection = DriverManager.getConnection(url, user, password); var statement = connection.createStatement()) {
                statement.execute("drop schema " + schema + " cascade");
            }
        }
    }

    @Test
    void scopedSqlSnapshotAndHeadCommitTogetherAndRevocationCannotReuseTheOldView() {
        provisionActiveCatalog();
        var repository = runtime(entityManager, null, null);
        assertNull(CatalogProjectionTenantContext.currentOrNull());
        assertNull(SecurityContextHolder.getContext().getAuthentication());
        var first = transaction(() -> repository.current(proof()));
        assertNull(CatalogProjectionTenantContext.currentOrNull());
        assertNull(SecurityContextHolder.getContext().getAuthentication());
        assertEquals(java.util.Set.of("app.read"), first.permissions());
        assertEquals(1L, count("select count(*) from rbac3_catalog_effective_snapshot"));
        assertEquals(1L, count("select count(*) from rbac3_catalog_snapshot_head"));
        transaction(() -> {
            entityManager.createNativeQuery("update rbac3_catalog_permission set governance_state='DISABLED', version=version+1, updated_at=current_timestamp, updated_by='test' where catalog_scope_id=1").executeUpdate();
            new JpaTenantAuthorizationStateRepository(entityManager, () -> NOW).increment(10L, "test");
            return null;
        });
        var after = transaction(() -> repository.current(proof()));
        assertNull(CatalogProjectionTenantContext.currentOrNull());
        assertTrue(after.permissions().isEmpty());
        assertTrue(after.policyVersion() > first.policyVersion());
        assertEquals(2L, count("select count(*) from rbac3_catalog_effective_snapshot"));
        assertEquals(after.policyVersion(), count("select tenant_policy_version from rbac3_catalog_snapshot_head where catalog_scope_id=1"));
    }

    @Test
    void factLoadFailureCleansTheVerifiedProjectionTenantWithoutPublishingAHead() {
        provisionActiveCatalog();
        failFactLoad = true;
        var repository = runtime(entityManager, null, null);
        assertNull(CatalogProjectionTenantContext.currentOrNull());

        var failure = assertThrows(Rbac3RuleViolation.class, () -> transaction(() -> repository.current(proof())));

        assertEquals("DIRECTORY_RUNTIME_UNAVAILABLE", failure.reasonCode());
        assertNull(CatalogProjectionTenantContext.currentOrNull());
        assertNull(SecurityContextHolder.getContext().getAuthentication());
        assertEquals(0L, count("select count(*) from rbac3_catalog_effective_snapshot"));
        assertEquals(0L, count("select count(*) from rbac3_catalog_snapshot_head"));
    }

    @Test
    void executionViewReadsTheActivatedPolicyAndRollsBackOnMissingResource() {
        provisionActiveCatalog();
        var request = proof();
        var repository = runtime(entityManager, null, null);
        var missing = new ExecutionGrantAuthorizationService.VerifiedExecution(request.binding(), request.issuer(),
                request.user().subject(), NOW.plusSeconds(60), "app.missing");
        assertEquals("AUTH_RUNTIME_EXECUTION_POLICY_UNAVAILABLE", assertThrows(Rbac3RuleViolation.class,
                () -> transaction(() -> repository.currentExecution(missing))).reasonCode());
        assertEquals(0L, count("select count(*) from rbac3_catalog_effective_snapshot"));
        assertEquals(0L, count("select count(*) from rbac3_catalog_snapshot_head"));
        var valid = new ExecutionGrantAuthorizationService.VerifiedExecution(request.binding(), request.issuer(),
                request.user().subject(), NOW.plusSeconds(60), "app.read");
        var current = transaction(() -> repository.currentExecution(valid));
        assertEquals("app.read", current.resource().key());
        assertTrue(current.resource().requirement().allows(current.snapshot().permissions()));
        assertEquals(NOW.plusSeconds(30), current.snapshot().expiresAt());
        transaction(() -> {
            entityManager.createNativeQuery("update rbac3_catalog_permission set governance_state='DISABLED', version=version+1, updated_at=current_timestamp, updated_by='test' where catalog_scope_id=1").executeUpdate();
            new JpaTenantAuthorizationStateRepository(entityManager, () -> NOW).increment(10L, "test");
            return null;
        });
        var revoked = transaction(() -> repository.currentExecution(valid));
        assertFalse(revoked.resource().requirement().allows(revoked.snapshot().permissions()));
        assertTrue(revoked.snapshot().policyVersion() > current.snapshot().policyVersion());
    }

    @Test
    void policyVersionIncrementUsesOptimisticCasAndRollsBack() throws Exception {
        long initial = count("select policy_version from rbac3_tenant_authorization_state where tenant_id=10");
        try (var em = factory.getObject().createEntityManager()) {
            em.getTransaction().begin();
            new JpaTenantAuthorizationStateRepository(em, () -> NOW).increment(10L, "rollback-test");
            em.getTransaction().rollback();
        }
        assertEquals(initial, count("select policy_version from rbac3_tenant_authorization_state where tenant_id=10"));

        var ready = new java.util.concurrent.CountDownLatch(2);
        var start = new java.util.concurrent.CountDownLatch(1);
        java.util.concurrent.Callable<Boolean> claim = () -> {
            try (var em = factory.getObject().createEntityManager()) {
                em.getTransaction().begin();
                try {
                    new JpaTenantAuthorizationStateRepository(em, () -> NOW).increment(10L, "cas-test");
                    ready.countDown();
                    if (!start.await(10, java.util.concurrent.TimeUnit.SECONDS)) throw new IllegalStateException("CAS_START_TIMEOUT");
                    em.getTransaction().commit();
                    return true;
                } catch (RuntimeException failure) {
                    if (em.getTransaction().isActive()) em.getTransaction().rollback();
                    Throwable cause = failure;
                    while (cause != null) {
                        if (cause instanceof jakarta.persistence.OptimisticLockException
                                || cause instanceof org.hibernate.StaleStateException) return false;
                        cause = cause.getCause();
                    }
                    throw failure;
                }
            }
        };
        try (var workers = java.util.concurrent.Executors.newFixedThreadPool(2)) {
            var first = workers.submit(claim);
            var second = workers.submit(claim);
            assertTrue(ready.await(10, java.util.concurrent.TimeUnit.SECONDS));
            start.countDown();
            assertNotEquals(first.get(20, java.util.concurrent.TimeUnit.SECONDS),
                    second.get(20, java.util.concurrent.TimeUnit.SECONDS));
        } finally {
            start.countDown();
        }
        assertEquals(initial + 1, count("select policy_version from rbac3_tenant_authorization_state where tenant_id=10"));
        var stateSql = recordedSql.stream().map(value -> value.toLowerCase(java.util.Locale.ROOT))
                .filter(value -> value.contains("rbac3_tenant_authorization_state")).toList();
        assertTrue(stateSql.stream().filter(value -> value.stripLeading().startsWith("select "))
                .noneMatch(value -> value.contains("for update")));
        assertTrue(stateSql.stream().anyMatch(value -> value.stripLeading().startsWith("update ")
                && value.contains("where") && value.contains("version")));
    }

    @Test
    void publicationRollbackLeavesNeitherAnImmutableSnapshotNorAHead() {
        provisionActiveCatalog();
        var repository = runtime(entityManager, null, null);
        assertThrows(IllegalStateException.class, () -> transaction(() -> {
            repository.current(proof());
            throw new IllegalStateException("controlled failure after head publication");
        }));
        assertEquals(0L, count("select count(*) from rbac3_catalog_effective_snapshot"));
        assertEquals(0L, count("select count(*) from rbac3_catalog_snapshot_head"));
    }

    @Test
    void concurrentRevocationWaitsForTheAuthorizationPointAndThenClosesTheNextRead() throws Exception {
        provisionActiveCatalog();
        long userId = count("select id from rbac3_user where tenant_id=10 and identity_sub='9001'");
        var entered = new java.util.concurrent.CountDownLatch(1);
        var release = new java.util.concurrent.CountDownLatch(1);
        try (var workers = java.util.concurrent.Executors.newFixedThreadPool(2)) {
            var reader = workers.submit(() -> {
                try (var em = factory.getObject().createEntityManager()) {
                    return inTransaction(em, () -> runtime(em, entered, release).current(proof()));
                }
            });
            assertTrue(entered.await(10, java.util.concurrent.TimeUnit.SECONDS));
            var revocationStarted = new java.util.concurrent.CountDownLatch(1);
            var writer = workers.submit(() -> {
                try (var em = factory.getObject().createEntityManager()) {
                    return inTransaction(em, () -> {
                        revocationStarted.countDown();
                        return em.createNativeQuery("update rbac3_user set status='DISABLED',auth_version=auth_version+1,version=version+1 where id=:id")
                                .setParameter("id", userId).executeUpdate();
                    });
                }
            });
            assertTrue(revocationStarted.await(5, java.util.concurrent.TimeUnit.SECONDS));
            try {
                assertThrows(java.util.concurrent.TimeoutException.class, () -> writer.get(150, java.util.concurrent.TimeUnit.MILLISECONDS));
            } finally { release.countDown(); }
            assertEquals(java.util.Set.of("app.read"), reader.get(10, java.util.concurrent.TimeUnit.SECONDS).permissions());
            assertEquals(1, writer.get(10, java.util.concurrent.TimeUnit.SECONDS));
        } finally { release.countDown(); }
        assertEquals("IDENTITY_INACTIVE", assertThrows(Rbac3RuleViolation.class,
                () -> transaction(() -> runtime(entityManager, null, null).current(proof()))).reasonCode());
    }

    @Test
    void sqlCheckpointClaimIsExclusiveAndCompletionIsTokenFenced() throws Exception {
        var start = new java.util.concurrent.CountDownLatch(1);
        java.util.concurrent.Callable<top.egon.cola.platform.tianquan.jianshen.admin.authorization.runtime.repository.ProjectionCheckpointRepository.Claim> call = () -> {
            start.await(5, java.util.concurrent.TimeUnit.SECONDS);
            try (var em = factory.getObject().createEntityManager()) {
                return inTransaction(em, () -> checkpoint(em).claimOwned("10", "event-1", "CATALOG", "1", 1));
            }
        };
        try (var workers = java.util.concurrent.Executors.newFixedThreadPool(2)) {
            var first = workers.submit(call); var second = workers.submit(call); start.countDown();
            var claims = List.of(first.get(10, java.util.concurrent.TimeUnit.SECONDS), second.get(10, java.util.concurrent.TimeUnit.SECONDS));
            assertEquals(1L, claims.stream().filter(claim -> claim.outcome() == top.egon.cola.platform.tianquan.jianshen.admin.authorization.runtime.domain.enums.RuntimeSnapshotRebuildClaimEnum.ACQUIRED).count());
            String token = claims.stream().map(top.egon.cola.platform.tianquan.jianshen.admin.authorization.runtime.repository.ProjectionCheckpointRepository.Claim::leaseToken).filter(java.util.Objects::nonNull).findFirst().orElseThrow();
            assertThrows(IllegalStateException.class, () -> transaction(() -> { checkpoint(entityManager).completeOwned("10", "event-1", "CATALOG", "1", 1, "stale"); return null; }));
            transaction(() -> { checkpoint(entityManager).completeOwned("10", "event-1", "CATALOG", "1", 1, token); return null; });
        }
    }

    private void provisionActiveCatalog() {
        SourceImportRequest source = register(); ready(source); var proof = qualify(source);
        transaction(() -> catalogs.activate(new CatalogActivationRequest(SCOPE, UUID.randomUUID().toString(), "0",
                List.of(new CatalogActivationRequest.Selection("api", "1", proof.qualificationId()))), authority));
        transaction(() -> {
            entityManager.createNativeQuery("""
                    insert into rbac3_role(id,tenant_id,application_id,role_code,role_name,role_type,risk_level,status,created_at,created_by,updated_at,updated_by)
                    values(40,10,20,'RUNTIME_TEST','Runtime test role','MANAGEMENT','LOW','ACTIVE',current_timestamp,'test',current_timestamp,'test')
                    """).executeUpdate();
            var roles = new top.egon.cola.platform.tianquan.jianshen.admin.authorization.grant.rolepermission.repository.RolePermissionGrantRepository(entityManager);
            roles.replace(scopes.lockScope(SCOPE), 40, new top.egon.cola.platform.tianquan.jianshen.admin.authorization.grant.rolepermission.domain.dto.ReplaceRolePermissionsRequestDTO(
                    SCOPE, List.of("app.read"), "0", NOW.minusSeconds(1), null), "test", NOW);
            return null;
        });
    }

    private PermissionRuntimeProofService.VerifiedRequest proof() {
        var digests = new top.egon.cola.platform.tianquan.jianshen.contract.permission.PermissionManifestCanonicalizer().digests(manifest());
        var binding = new PermissionRuntimeProperties.Binding(SCOPE, java.net.URI.create("https://app.example"), authority.issuer(), "pipeline", "pipeline-app",
                "infra", "publisher", "test", java.net.URI.create("https://rbac.example"), "api", "1", "f".repeat(64), digests.policyDigest(), digests.manifestDigest(), true);
        var user = new top.egon.cola.platform.tianquan.shoubing.contract.IdentityPrincipal("9001", "10", "9002", java.util.Set.of("https://app.example"),
                NOW.minusSeconds(1), NOW.plusSeconds(300), top.egon.cola.platform.tianquan.shoubing.contract.AuthenticationContext.of("PASSWORD", NOW.minusSeconds(10)));
        return new PermissionRuntimeProofService.VerifiedRequest(binding, authority.issuer(), user);
    }

    private PermissionRuntimeSnapshotRepository runtime(EntityManager em, java.util.concurrent.CountDownLatch entered,
                                                        java.util.concurrent.CountDownLatch release) {
        var facts = mock(top.egon.cola.platform.tianquan.jianshen.admin.authorization.runtime.activation.repository.RoleActivationFactRepository.class);
        var roots = mock(top.egon.cola.platform.tianquan.jianshen.admin.authorization.runtime.activation.repository.ActivationTransaction.class);
        var eligibility = mock(top.egon.cola.platform.tianquan.jianshen.admin.iam.role.service.RoleEligibilityService.class);
        when(eligibility.isEffectiveForProjection(any(),any(),any(),any())).thenAnswer(invocation -> {
            assertEquals(invocation.getArgument(0), CatalogProjectionTenantContext.currentOrNull(),
                    "Every catalog eligibility read requires the verified projection tenant");
            assertNull(SecurityContextHolder.getContext().getAuthentication(), "Projection must not manufacture authentication");
            return true;
        });
        when(facts.load(any(),any(),any())).thenAnswer(invocation -> {
            // The real JPA facts loader repeats eligibility while constructing the role hierarchy.
            assertTrue(eligibility.isEffectiveForProjection(invocation.getArgument(0), invocation.getArgument(1),
                    "20", invocation.getArgument(2)));
            if (failFactLoad) throw new Rbac3RuleViolation("DIRECTORY_RUNTIME_UNAVAILABLE");
            if (entered != null) { entered.countDown(); assertTrue(release.await(10, java.util.concurrent.TimeUnit.SECONDS)); }
            Object[] user = (Object[]) em.createNativeQuery("select id,auth_version from rbac3_user where tenant_id=10 and identity_sub='9001'").getSingleResult();
            long policy = ((Number) em.createNativeQuery("select policy_version from rbac3_tenant_authorization_state where tenant_id=10").getSingleResult()).longValue();
            var hierarchy = new top.egon.cola.platform.tianquan.jianshen.core.hierarchy.RoleHierarchy(List.of(
                    new top.egon.cola.platform.tianquan.jianshen.core.hierarchy.RoleNode("40","20","RUNTIME_TEST",true,
                            top.egon.cola.platform.tianquan.jianshen.core.hierarchy.RoleNode.RiskLevel.LOW,false,null,0)),List.of());
            return new top.egon.cola.platform.tianquan.jianshen.admin.authorization.runtime.activation.domain.vo.ActivationFactsVO("10",user[0].toString(),hierarchy,
                    List.of(new top.egon.cola.platform.tianquan.jianshen.core.activation.EligibleAssignmentFact("50",user[0].toString(),"40",
                            top.egon.cola.platform.tianquan.jianshen.core.activation.EligibleAssignmentFact.Status.ACTIVE,NOW.minusSeconds(100),null)),List.of(),
                    new top.egon.cola.platform.tianquan.jianshen.core.activation.AuthorizationRuleFacts(List.of(),List.of(),List.of(),List.of(),List.of()),
                    ((Number)user[1]).longValue(),policy,"directory:0",Map.of("20",new top.egon.cola.platform.tianquan.jianshen.admin.authorization.runtime.activation.domain.vo.ApplicationFactVO("20","app","App")),Map.of("40","Runtime"));
        });
        when(roots.current(any(),any(),any(),any())).thenReturn(new top.egon.cola.platform.tianquan.jianshen.admin.authorization.runtime.activation.domain.vo.CurrentStateVO(Map.of("20",java.util.Set.of("40")),0,0,"initial",false));
        return new PermissionRuntimeSnapshotRepository(em,new ObjectMapper().registerModule(new JavaTimeModule()),facts,roots,eligibility,()->NOW,
                new PermissionRuntimeProperties(java.time.Duration.ofSeconds(30),List.of(proof().binding())),ids::incrementAndGet);
    }

    private top.egon.cola.platform.tianquan.jianshen.admin.authorization.runtime.repository.postgresql.PostgresqlProjectionCheckpointRepository checkpoint(EntityManager em) {
        return new top.egon.cola.platform.tianquan.jianshen.admin.authorization.runtime.repository.postgresql.PostgresqlProjectionCheckpointRepository(
                new top.egon.cola.platform.tianquan.jianshen.admin.authorization.runtime.repository.postgresql.PostgresqlRuntimeProjectionRepository(em,
                        new ObjectMapper().registerModule(new JavaTimeModule())),java.time.Clock.systemUTC());
    }
    private <T> T inTransaction(EntityManager em, Supplier<T> work) {
        em.getTransaction().begin();
        try { T result=work.get();em.getTransaction().commit();return result; }
        catch(RuntimeException failure){if(em.getTransaction().isActive())em.getTransaction().rollback();throw failure;}
    }

    private SourceImportRequest register() {
        return transaction(() -> {
            var plan = plans.plan(new ManifestRegistrationRequest.Plan(SCOPE, manifest(), "0", "0"), authority);
            registrations.register(new ManifestRegistrationRequest.Apply(SCOPE, "api", plan.planId(), OPERATION, plan.digests(), "0", "0"), authority);
            return manifests.sourceImport(SCOPE, "api", 1);
        });
    }

    private void ready(SourceImportRequest source) {
        transaction(() -> {
            receipts.accept(source, new SourceImportReceipt("300", source.operationId(), SCOPE, "api", "1", source.sourceVersion(), source.digests(),
                    source.projectionDigest(), source.resourceIds().size(), source.permissionIds().size(), source.manifest().messages().size(), NOW));
            return null;
        });
    }

    private DeploymentQualificationReceiptVO qualify(SourceImportRequest source) {
        return transaction(() -> deployment.qualify(new DeploymentQualificationRequest(SCOPE, "api", "1", "f".repeat(64), source.digests().manifestDigest(),
                source.digests().policyDigest(), "pipeline", "build", "refs/heads/main", "a".repeat(40), "deployment",
                new DeploymentQualificationRequest.Readiness("f".repeat(64), source.digests().manifestDigest(), source.digests().policyDigest(), true, true, true, NOW)), authority));
    }

    private long count(String sql) { return transaction(() -> ((Number) entityManager.createNativeQuery(sql).getSingleResult()).longValue()); }

    private <T> T transaction(Supplier<T> action) {
        var transaction = entityManager.getTransaction();
        transaction.begin();
        try {
            T result = action.get();
            transaction.commit();
            entityManager.clear();
            return result;
        } catch (RuntimeException failure) {
            if (transaction.isActive()) transaction.rollback();
            entityManager.clear();
            throw failure;
        }
    }

    private static String environment(String name) {
        String value = System.getenv(name);
        if (value == null || value.isBlank()) throw new IllegalStateException(name + " is required by the explicit PostgreSQL profile");
        return value.strip();
    }
}
