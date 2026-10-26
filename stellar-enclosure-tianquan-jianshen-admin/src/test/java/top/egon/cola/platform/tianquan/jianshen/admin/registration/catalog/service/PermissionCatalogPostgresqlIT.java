package top.egon.cola.platform.tianquan.jianshen.admin.registration.catalog.service;

import top.egon.cola.platform.tianquan.jianshen.admin.registration.catalog.repository.CatalogAdministrationGuard;

import top.egon.cola.platform.tianquan.jianshen.admin.registration.catalog.domain.convertor.PermissionCatalogJson;
import top.egon.cola.platform.tianquan.jianshen.admin.registration.catalog.domain.vo.DeploymentQualificationReceiptVO;
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
import static top.egon.cola.platform.tianquan.jianshen.admin.registration.catalog.service.PermissionCatalogFixture.*;

/** Explicit PostgreSQL-only profile. Creates and drops only an owned random schema; never starts an external process. */
class PermissionCatalogPostgresqlIT {
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

    @org.junit.jupiter.api.BeforeAll
    static void initializeIds() {
        top.egon.cola.component.common.id.snowflake.SnowflakeIdGenerator.initialize(0L, java.time.Duration.ofMillis(5));
    }

    @BeforeEach
    void connectToExplicitExistingDatabase() throws Exception {
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
        assertEquals("16", flyway.info().current().getVersion().getVersion());
        var dataSource = new DriverManagerDataSource(url, user, password);
        var properties = new Properties();
        properties.setProperty("currentSchema", schema);
        dataSource.setConnectionProperties(properties);
        factory = new LocalContainerEntityManagerFactoryBean();
        factory.setDataSource(dataSource);
        factory.setJpaVendorAdapter(new HibernateJpaVendorAdapter());
        factory.setPackagesToScan("top.egon.cola.platform.tianquan.jianshen.admin.authorization.runtime.state.domain.po");
        factory.setJpaPropertyMap(Map.of("hibernate.hbm2ddl.auto", "none", "hibernate.default_schema", schema, "hibernate.show_sql", false));
        factory.afterPropertiesSet();
        entityManager = factory.getObject().createEntityManager();
        json = new PermissionCatalogJson(new ObjectMapper().registerModule(new JavaTimeModule()));
        scopes = new PermissionCatalogScopeRepository(entityManager, json);
        manifests = new PermissionManifestRepository(entityManager, json);
        activations = new PermissionCatalogActivationRepository(entityManager, json);
        qualifications = new DeploymentQualificationRepository(entityManager, json);
        var definitions = new PermissionCatalogDefinitionRepository(entityManager);
        var events = mock(AuthorizationEventPublisher.class);
        plans = new PermissionManifestPlanService(scopes, definitions, manifests, audit, () -> NOW, ids::incrementAndGet);
        registrations = new PermissionManifestRegistrationService(scopes, definitions, manifests, events, audit, () -> NOW, mock(PermissionSourceOutboxRepository.class));
        receipts = new PermissionSourceReceiptService(scopes, manifests, audit, () -> NOW, mock(PermissionSourceOutboxRepository.class));
        deployment = new DeploymentQualificationService(scopes, manifests, qualifications, json, audit, () -> NOW, ids::incrementAndGet);
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
    void actualRepositoriesRegisterReceiptQualifyAndAtomicallyActivateOneDescriptor() {
        SourceImportRequest source = register();
        assertEquals("METADATA_PENDING", transaction(() -> manifests.findVersion(SCOPE, "api", 1).orElseThrow().state()));
        assertEquals(0L, count("select revision from rbac3_catalog_active_pointer where catalog_scope_id=1"));
        ready(source);
        var qualification = qualify(source);
        var request = new CatalogActivationRequest(SCOPE, UUID.randomUUID().toString(), "0", List.of(new CatalogActivationRequest.Selection("api", "1", qualification.qualificationId())));
        var descriptor = transaction(() -> catalogs.activate(request, authority));
        assertEquals(descriptor, transaction(() -> catalogs.descriptor(SCOPE, "api", 1, authority)));
        assertEquals(descriptor, transaction(() -> catalogs.activate(request, authority)));
        assertEquals(1L, count("select revision from rbac3_catalog_active_pointer where catalog_scope_id=1"));
        assertThrows(Rbac3RuleViolation.class, () -> transaction(() -> catalogs.activate(new CatalogActivationRequest(SCOPE,
                UUID.randomUUID().toString(), "0", request.producers()), authority)));
        assertEquals(1L, count("select count(*) from rbac3_catalog_activation"));
    }

    @Test
    void staleDeliveryGenerationCannotFailAResumedManifest() {
        SourceImportRequest source = register();
        transaction(() -> {
            assertTrue(manifests.markFailed(source, 1, "METADATA_DELIVERY_EXHAUSTED", NOW));
            assertEquals(3, manifests.restartMetadata(source, 2, NOW));
            assertFalse(manifests.markFailed(source, 1, "METADATA_LATE_FAILURE", NOW));
            var current = manifests.findVersion(SCOPE, "api", 1).orElseThrow();
            assertEquals("METADATA_PENDING", current.state());
            assertEquals(3, current.metadataRevision());
            return null;
        });
        ready(source);
        assertEquals("READY", transaction(() -> manifests.findVersion(SCOPE, "api", 1).orElseThrow().state()));
    }

    @Test
    void auditFailureRollsBackCandidateIdsAndProducerHead() {
        var calls = new java.util.concurrent.atomic.AtomicInteger();
        doAnswer(invocation -> {
            if (calls.incrementAndGet() == 2) throw new IllegalStateException("controlled audit outage");
            return null;
        }).when(audit).record(any());
        assertThrows(IllegalStateException.class, this::register);
        assertEquals(0L, count("select count(*) from rbac3_catalog_manifest"));
        assertEquals(0L, count("select current_revision from rbac3_catalog_producer where catalog_scope_id=1 and producer_id='api'"));
    }

    @Test
    void retiredIdentityBlocksRollbackAndQualificationGrantRevocationIsImmediate() {
        SourceImportRequest source = register();
        ready(source);
        var qualification = qualify(source);
        var request = new CatalogActivationRequest(SCOPE, UUID.randomUUID().toString(), "0", List.of(new CatalogActivationRequest.Selection("api", "1", qualification.qualificationId())));
        transaction(() -> {
            entityManager.createNativeQuery("update rbac3_catalog_permission set governance_state='RETIRED',version=version+1,updated_at=current_timestamp,updated_by='test' where catalog_scope_id=1").executeUpdate();
            return null;
        });
        assertThrows(Rbac3RuleViolation.class, () -> transaction(() -> catalogs.activate(request, authority)));
        assertEquals(0L, count("select revision from rbac3_catalog_active_pointer where catalog_scope_id=1"));
        transaction(() -> {
            entityManager.createNativeQuery("update rbac3_catalog_service_grant set enabled=false,version=version+1,updated_at=current_timestamp,updated_by='test' where id=30").executeUpdate();
            return null;
        });
        assertThrows(Rbac3RuleViolation.class, () -> transaction(() -> qualifications.requireTrusted(SCOPE, "api", 1,
                Long.parseLong(qualification.qualificationId()), NOW)));
    }

    @Test
    void directPermissionGrantRequiresActivatedCodeAndFullReplacementRevokesFutureGrant() {
        SourceImportRequest source = register();
        transaction(() -> {
            entityManager.createNativeQuery("""
                    insert into rbac3_role(id,tenant_id,application_id,role_code,role_name,role_type,risk_level,status,created_at,created_by,updated_at,updated_by)
                    values(40,10,20,'CATALOG_TEST','Catalog test role','MANAGEMENT','LOW','ACTIVE',current_timestamp,'test',current_timestamp,'test')
                    """).executeUpdate();
            return null;
        });
        var repository = new top.egon.cola.platform.tianquan.jianshen.admin.authorization.grant.rolepermission.repository.RolePermissionGrantRepository(entityManager);
        var request = new top.egon.cola.platform.tianquan.jianshen.admin.authorization.grant.rolepermission.domain.dto.ReplaceRolePermissionsRequestDTO(
                SCOPE, List.of("app.read"), "0", NOW.plusSeconds(3600), null);
        assertThrows(Rbac3RuleViolation.class, () -> transaction(() -> repository.replace(scopes.lockScope(SCOPE), 40, request, "test", NOW)));
        assertEquals(0L, count("select count(*) from rbac3_catalog_role_permission"));
        ready(source);
        var qualification = qualify(source);
        transaction(() -> catalogs.activate(new CatalogActivationRequest(SCOPE, UUID.randomUUID().toString(), "0",
                List.of(new CatalogActivationRequest.Selection("api", "1", qualification.qualificationId()))), authority));
        assertEquals("1", transaction(() -> repository.replace(scopes.lockScope(SCOPE), 40, request, "test", NOW)).version());
        assertThrows(Rbac3RuleViolation.class, () -> transaction(() -> repository.replace(scopes.lockScope(SCOPE), 40, request, "test", NOW)));
        assertEquals(1L, count("select count(*) from rbac3_catalog_role_permission where status='ACTIVE'"));
        transaction(() -> repository.replace(scopes.lockScope(SCOPE), 40,
                new top.egon.cola.platform.tianquan.jianshen.admin.authorization.grant.rolepermission.domain.dto.ReplaceRolePermissionsRequestDTO(SCOPE, List.of(), "1", null, null), "test", NOW));
        assertEquals(0L, count("select count(*) from rbac3_catalog_role_permission where status='ACTIVE'"));
        assertEquals(1L, count("select count(*) from rbac3_catalog_role_permission"));
    }

    @Test
    void governanceTransferPreservesDisabledIdentityAndInvalidatesOldProducerPlan() {
        SourceImportRequest source = register();
        var repository = new top.egon.cola.platform.tianquan.jianshen.admin.authorization.catalog.repository.CatalogGovernanceRepository(entityManager, scopes, json);
        transaction(() -> {
            entityManager.createNativeQuery("""
                    insert into rbac3_catalog_producer(catalog_scope_id,producer_id,kind,owned_key_prefixes,owned_permission_prefixes,owned_message_prefixes,expected_modules,enabled,created_at,created_by,updated_at,updated_by)
                    values(1,'next-api','JAVA','["app."]','["app."]','["next/"]','["next"]',true,current_timestamp,'test',current_timestamp,'test')
                    """).executeUpdate();
            return null;
        });
        var kind = top.egon.cola.platform.tianquan.jianshen.admin.authorization.catalog.domain.dto.CatalogGovernanceCommandDTO.Kind.RESOURCE;
        var disable = new top.egon.cola.platform.tianquan.jianshen.admin.authorization.catalog.domain.dto.CatalogGovernanceCommandDTO(SCOPE, kind,
                source.resourceIds().get("app.read"), top.egon.cola.platform.tianquan.jianshen.admin.authorization.catalog.domain.dto.CatalogGovernanceCommandDTO.Action.DISABLE, "0", null);
        transaction(() -> { scopes.lockScope(SCOPE); return repository.mutate(disable, "test", NOW); });
        var transfer = new top.egon.cola.platform.tianquan.jianshen.admin.authorization.catalog.domain.dto.CatalogGovernanceCommandDTO(SCOPE, kind,
                disable.identityId(), top.egon.cola.platform.tianquan.jianshen.admin.authorization.catalog.domain.dto.CatalogGovernanceCommandDTO.Action.TRANSFER, "1", "next-api");
        var result = transaction(() -> { scopes.lockScope(SCOPE); return repository.mutate(transfer, "test", NOW); });
        assertEquals(disable.identityId(), result.after().id());
        assertEquals("DISABLED", result.after().state());
        assertEquals("next-api", result.after().producerId());
        assertEquals(3L, count("select version from rbac3_catalog_producer where catalog_scope_id=1 and producer_id='api'"));
        assertEquals(1L, count("select version from rbac3_catalog_producer where catalog_scope_id=1 and producer_id='next-api'"));
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
