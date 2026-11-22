package top.egon.cola.platform.tianquan.jianshen.admin.registration.catalog.service;

import top.egon.cola.platform.tianquan.jianshen.admin.authorization.grant.rolepermission.domain.dto.ReplaceRolePermissionsRequestDTO;
import top.egon.cola.platform.tianquan.jianshen.admin.authorization.grant.rolepermission.repository.RolePermissionGrantRepository;
import top.egon.cola.platform.tianquan.jianshen.admin.registration.catalog.repository.DeploymentQualificationRepository;
import top.egon.cola.platform.tianquan.jianshen.admin.registration.catalog.repository.CatalogAdministrationGuard;
import top.egon.cola.platform.tianquan.jianshen.admin.authorization.runtime.state.repository.jpa.JpaTenantAuthorizationStateRepository;
import top.egon.cola.platform.tianquan.jianshen.contract.permission.SourceImportReceipt;
import top.egon.cola.platform.tianquan.jianshen.contract.permission.DeploymentQualificationRequest;
import top.egon.cola.platform.tianquan.jianshen.admin.registration.catalog.domain.convertor.PermissionCatalogJson;
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
import org.springframework.test.util.ReflectionTestUtils;
import top.egon.cola.platform.tianquan.jianshen.admin.audit.service.AuditQueryService;
import top.egon.cola.platform.tianquan.jianshen.admin.authorization.runtime.activation.repository.ActivationTransaction;
import top.egon.cola.platform.tianquan.jianshen.admin.authorization.runtime.activation.repository.RoleActivationFactRepository;
import top.egon.cola.platform.tianquan.jianshen.admin.authorization.runtime.catalog.PermissionRuntimeProperties;
import top.egon.cola.platform.tianquan.jianshen.admin.authorization.runtime.catalog.PermissionRuntimeSnapshotRepository;
import top.egon.cola.platform.tianquan.jianshen.admin.authorization.runtime.repository.AuthorizationEventPublisher;
import top.egon.cola.platform.tianquan.jianshen.admin.iam.role.service.RoleEligibilityService;
import top.egon.cola.platform.tianquan.jianshen.admin.registration.catalog.domain.PermissionCatalogCaller;
import top.egon.cola.platform.tianquan.jianshen.admin.registration.catalog.repository.PermissionCatalogActivationRepository;
import top.egon.cola.platform.tianquan.jianshen.admin.registration.catalog.repository.PermissionCatalogDefinitionRepository;
import top.egon.cola.platform.tianquan.jianshen.admin.registration.catalog.repository.PermissionCatalogScopeRepository;
import top.egon.cola.platform.tianquan.jianshen.admin.registration.catalog.repository.PermissionManifestRepository;
import top.egon.cola.platform.tianquan.jianshen.admin.registration.catalog.repository.PermissionSourceOutboxRepository;
import top.egon.cola.platform.tianquan.jianshen.contract.permission.CatalogActivationRequest;
import top.egon.cola.platform.tianquan.jianshen.contract.permission.ManifestRegistrationRequest;
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
import static org.mockito.Mockito.*;
import static top.egon.cola.platform.tianquan.jianshen.admin.registration.catalog.service.PermissionCatalogFixture.*;

/** Explicit dedicated PostgreSQL test database only: the public schema must be empty and is cleaned after this test.
 * ShardingSphere binds unqualified PostgreSQL tables in public, matching the production topology. */
class PermissionCatalogRoutedPostgresqlIT {
    private String url;
    private String user;
    private String password;
    private String schema;
    private boolean schemaCreated;
    private LocalContainerEntityManagerFactoryBean factory;
    private EntityManager entityManager;
    private javax.sql.DataSource logicalDataSource;
    private com.zaxxer.hikari.HikariDataSource routedPhysicalDataSource;
    private PermissionCatalogJson json;
    private PermissionCatalogScopeRepository scopes;
    private PermissionManifestRepository manifests;
    private PermissionCatalogActivationRepository activations;
    private PermissionManifestPlanService plans;
    private PermissionManifestRegistrationService registrations;
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
        if (!url.matches("jdbc:postgresql://[^/?]+/[A-Za-z0-9_]+_route_test")) {
            throw new IllegalArgumentException("routed IT requires an explicitly dedicated *_route_test database");
        }
        schema = "public";
        try (var connection = DriverManager.getConnection(url, user, password); var statement = connection.createStatement();
             var objects = statement.executeQuery("select (select count(*) from pg_class where relnamespace='public'::regnamespace)+(select count(*) from pg_proc where pronamespace='public'::regnamespace)+(select count(*) from pg_type where typnamespace='public'::regnamespace)")) {
            objects.next();
            assertEquals(0, objects.getInt(1), "the dedicated routed test database public schema must be empty");
            schemaCreated = true;
        }
        var flyway = Flyway.configure().dataSource(url, user, password).defaultSchema(schema).schemas(schema)
                .table("flyway_schema_history_rbac3").locations("classpath:db/migration")
                .initSql("SET rbac3.bootstrap.tenant_ids = '10'; SET rbac3.bootstrap.identity_sub = '9001'").load();
        flyway.migrate();
        assertTrue(flyway.validateWithResult().validationSuccessful);

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
        var definitions = new PermissionCatalogDefinitionRepository(entityManager);
        var events = mock(AuthorizationEventPublisher.class);
        plans = new PermissionManifestPlanService(scopes, definitions, manifests, audit, () -> NOW, ids::incrementAndGet);
        registrations = new PermissionManifestRegistrationService(scopes, definitions, manifests, events, audit, () -> NOW, mock(PermissionSourceOutboxRepository.class));
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
                    insert into rbac3_catalog_producer(catalog_scope_id,producer_id,kind,owned_key_prefixes,owned_permission_prefixes,owned_message_prefixes,expected_modules,enabled,created_at,created_by,updated_at,updated_by)
                    values(1,'other','JAVA','["other."]','["other."]','["other/"]','["other"]',false,current_timestamp,'test',current_timestamp,'test')
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
        if (logicalDataSource instanceof AutoCloseable closeable) closeable.close();
        if (routedPhysicalDataSource != null) routedPhysicalDataSource.close();
        if (schemaCreated && "public".equals(schema)) {
            try (var connection = DriverManager.getConnection(url, user, password); var statement = connection.createStatement()) {
                statement.execute("drop schema public cascade");
                statement.execute("create schema public");
            }
        }
    }

    @Test
    void exactSelectedClosureWorksThroughProductionSingleRoutingAndRetainsGovernanceAndMessageOwnership() throws Exception {
        register();
        switchToLogicalDataSource();
        var request = new CatalogActivationRequest(SCOPE, UUID.randomUUID().toString(), "0",
                List.of(new CatalogActivationRequest.Selection("api", "1", "1")));
        transaction(() -> { activations.requireComplete(request); activations.requireReferenceClosure(request); return null; });
        assertRejectedAfter("update rbac3_catalog_resource set governance_state='RETIRED',version=version+1", request);
        assertRejectedAfter("update rbac3_catalog_permission set governance_state='RETIRED',version=version+1", request);
        assertRejectedAfter("update rbac3_catalog_message_owner set lifecycle='DISABLED',version=version+1", request);
        assertRejectedAfter("update rbac3_catalog_resource set owner_producer_id='other',version=version+1", request);
        assertRejectedAfter("update rbac3_catalog_permission set owner_producer_id='other',version=version+1", request);
        assertRejectedAfter("update rbac3_catalog_message_owner set owner_producer_id='other',version=version+1", request);
        transaction(() -> { activations.requireReferenceClosure(request); return null; });
    }

    @Test
    void activeRoleUserReadMaterializesWithinTheRoutedQueryAndPreservesIdentityBoundaries() throws Exception {
        transaction(() -> {
            entityManager.createNativeQuery("""
                    insert into rbac3_user(id,tenant_id,identity_sub,status,auth_version,version,created_at,created_by,updated_at,updated_by)
                    values(901,10,'route-user','ACTIVE',0,0,current_timestamp,'test',current_timestamp,'test')
                    """).executeUpdate();
            entityManager.createNativeQuery("""
                    insert into rbac3_role(id,tenant_id,application_id,role_code,role_name,role_type,risk_level,status,created_at,created_by,updated_at,updated_by)
                    values(40,10,20,'ROUTED_ACTIVE_ROLE','Routed active role','MANAGEMENT','LOW','ACTIVE',current_timestamp,'test',current_timestamp,'test')
                    """).executeUpdate();
            entityManager.createNativeQuery("""
                    insert into rbac3_user_active_role(tenant_id,user_id,application_id,root_role_id,eligible_assignment_ids,activated_at)
                    values(10,901,20,40,'["50"]',current_timestamp)
                    """).executeUpdate();
            return null;
        });
        switchToLogicalDataSource();
        var routedEntityManager = org.springframework.orm.jpa.SharedEntityManagerCreator.createSharedEntityManager(factory.getObject());
        var transactions = new org.springframework.transaction.support.TransactionTemplate(new org.springframework.orm.jpa.JpaTransactionManager(factory.getObject()));
        var repository = new top.egon.cola.platform.tianquan.jianshen.admin.authorization.runtime.activation.repository.jpa.JpaUserActiveRoleRepository(routedEntityManager);
        var selected = transactions.execute(status -> {
            routedEntityManager.createNativeQuery("select id,auth_version from rbac3_user where tenant_id=10 and id=901").getResultList();
            routedEntityManager.createNativeQuery("select policy_version from rbac3_tenant_authorization_state where tenant_id=10").getSingleResult();
            routedEntityManager.createNativeQuery("select id from rbac3_role where tenant_id=10 and application_id=20").getResultList();
            return repository.current("10", "route-user", "901", NOW);
        });
        assertEquals(Map.of("20", java.util.Set.of("40")), selected.rootsByApplication());
        assertThrows(IllegalArgumentException.class, () -> transactions.execute(status -> repository.current("10", "foreign-subject", "901", NOW)));
        assertThrows(IllegalArgumentException.class, () -> transactions.execute(status -> repository.current("11", "route-user", "901", NOW)));
        assertThrows(IllegalArgumentException.class, () -> transactions.execute(status -> repository.current("10", "route-user", "902", NOW)));
        assertEquals(1L, transaction(() -> ((Number) entityManager.createNativeQuery(
                "select count(*) from rbac3_user_active_role where tenant_id=10 and user_id=901").getSingleResult()).longValue()));
    }

    @Test
    void activeRolePermissionReplacementAddsClearsAndRejectsInvalidOrStaleRequestsThroughRouting() throws Exception {
        var source = register();
        activate(source);
        transaction(() -> {
            entityManager.createNativeQuery("""
                    insert into rbac3_role(id,tenant_id,application_id,role_code,role_name,role_type,risk_level,status,created_at,created_by,updated_at,updated_by)
                    values(40,10,20,'CATALOG_ROUTED_TEST','Routed catalog test role','MANAGEMENT','LOW','ACTIVE',current_timestamp,'test',current_timestamp,'test')
                    """).executeUpdate();
            return null;
        });
        switchToLogicalDataSource();
        var grants = new RolePermissionGrantRepository(entityManager);
        var scope = new PermissionCatalogScopeRepository.ScopeState(SCOPE, 20, 1, 1);
        var add = new ReplaceRolePermissionsRequestDTO(
                SCOPE, List.of("app.read"), "0", NOW.plusSeconds(60), NOW.plusSeconds(3600));
        var added = transaction(() -> grants.replace(scope, 40, add, "test", NOW));
        assertEquals(new RolePermissionGrantRepository.Mutation("1", 1, 0), added);
        var actual = transaction(() -> grants.read(scope, 40));
        assertEquals(List.of("app.read"), actual.permissions().stream().map(permission -> permission.permissionCode()).toList());
        assertEquals(add.validFrom(), actual.permissions().getFirst().validFrom());
        assertEquals(add.validTo(), actual.permissions().getFirst().validTo());
        var snapshots = new PermissionRuntimeSnapshotRepository(entityManager, new ObjectMapper(),
                mock(RoleActivationFactRepository.class), mock(ActivationTransaction.class), mock(RoleEligibilityService.class),
                () -> NOW, new PermissionRuntimeProperties(null, List.of()));
        assertEquals(List.of("app.read"), transaction(() -> ReflectionTestUtils.<List<String>>invokeMethod(
                snapshots, "permissions", 1L, 1L, List.of("40"), NOW.plusSeconds(300))));
        var stale = assertThrows(Rbac3RuleViolation.class, () -> transaction(() -> grants.replace(scope, 40, add, "test", NOW)));
        assertEquals("RESOURCE_VERSION_CONFLICT", stale.reasonCode());
        var invalid = new ReplaceRolePermissionsRequestDTO(
                SCOPE, List.of("app.missing"), "1", null, null);
        assertEquals("RESOURCE_NOT_FOUND", assertThrows(Rbac3RuleViolation.class,
                () -> transaction(() -> grants.replace(scope, 40, invalid, "test", NOW))).reasonCode());
        assertEquals(actual, transaction(() -> grants.read(scope, 40)));
        var clear = new ReplaceRolePermissionsRequestDTO(
                SCOPE, List.of(), "1", null, null);
        var removed = transaction(() -> grants.replace(scope, 40, clear, "test", NOW));
        assertEquals(new RolePermissionGrantRepository.Mutation("2", 0, 1), removed);
        assertTrue(transaction(() -> grants.read(scope, 40)).permissions().isEmpty());
        assertEquals(List.of(), transaction(() -> ReflectionTestUtils.<List<String>>invokeMethod(
                snapshots, "permissions", 1L, 1L, List.of("40"), NOW.plusSeconds(300))));
        assertEquals(1L, transaction(() -> ((Number) entityManager.createNativeQuery(
                "select count(*) from rbac3_catalog_role_permission where catalog_scope_id=1 and role_id=40 and status='DISABLED'").getSingleResult()).longValue()));
    }

    private void activate(SourceImportRequest source) {
        var receipts = new PermissionSourceReceiptService(scopes, manifests, audit, () -> NOW, mock(PermissionSourceOutboxRepository.class));
        transaction(() -> {
            receipts.accept(source, new SourceImportReceipt("300", source.operationId(), SCOPE,
                    "api", "1", source.sourceVersion(), source.digests(), source.projectionDigest(), source.resourceIds().size(),
                    source.permissionIds().size(), source.manifest().messages().size(), NOW));
            return null;
        });
        var qualifications = new DeploymentQualificationRepository(entityManager, json);
        var deployment = new DeploymentQualificationService(scopes, manifests, qualifications, json, audit, () -> NOW, ids::incrementAndGet);
        var qualification = transaction(() -> deployment.qualify(new DeploymentQualificationRequest(SCOPE,
                "api", "1", "f".repeat(64), source.digests().manifestDigest(), source.digests().policyDigest(), "pipeline", "build", "refs/heads/main",
                "a".repeat(40), "deployment", new DeploymentQualificationRequest.Readiness(
                "f".repeat(64), source.digests().manifestDigest(), source.digests().policyDigest(), true, true, true, NOW)), authority));
        var catalogs = new PermissionCatalogActivationService(scopes, manifests, qualifications, activations,
                new JpaTenantAuthorizationStateRepository(entityManager, () -> NOW),
                mock(AuthorizationEventPublisher.class), audit, () -> NOW,
                mock(CatalogAdministrationGuard.class));
        transaction(() -> catalogs.activate(new CatalogActivationRequest(SCOPE, UUID.randomUUID().toString(), "0",
                List.of(new CatalogActivationRequest.Selection("api", "1", qualification.qualificationId()))), authority));
    }

    private void assertRejectedAfter(String sql, CatalogActivationRequest request) {
        var transaction = entityManager.getTransaction();
        transaction.begin();
        try {
            entityManager.createNativeQuery(sql).executeUpdate();
            assertThrows(Rbac3RuleViolation.class, () -> activations.requireReferenceClosure(request));
        } finally {
            transaction.rollback();
            entityManager.clear();
        }
    }

    private void switchToLogicalDataSource() throws Exception {
        entityManager.close();
        factory.destroy();
        routedPhysicalDataSource = new com.zaxxer.hikari.HikariDataSource();
        routedPhysicalDataSource.setJdbcUrl(url);
        routedPhysicalDataSource.setUsername(user);
        routedPhysicalDataSource.setPassword(password);
        routedPhysicalDataSource.setSchema(schema);
        routedPhysicalDataSource.setMaximumPoolSize(4);
        routedPhysicalDataSource.setConnectionTimeout(5_000);
        String yaml;
        try (var source = getClass().getResourceAsStream("/rbac-sharding-native.yml")) {
            assertNotNull(source);
            yaml = new String(source.readAllBytes(), StandardCharsets.UTF_8)
                    .replace("rbac_primary.public.", "rbac_primary." + schema + ".")
                    .lines().filter(line -> !line.contains("rbac_primary.egon_outbox."))
                    .collect(Collectors.joining("\n"));
        }
        logicalDataSource = org.apache.shardingsphere.driver.api.yaml.YamlShardingSphereDataSourceFactory
                .createDataSource(Map.of("rbac_primary", routedPhysicalDataSource), yaml.getBytes(StandardCharsets.UTF_8));
        factory = new LocalContainerEntityManagerFactoryBean();
        factory.setDataSource(logicalDataSource);
        factory.setJpaVendorAdapter(new HibernateJpaVendorAdapter());
        factory.setPackagesToScan("top.egon.cola.platform.tianquan.jianshen.admin.authorization.runtime.state.domain.po",
                "top.egon.cola.platform.tianquan.jianshen.admin.iam.user.domain.po",
                "top.egon.cola.platform.tianquan.jianshen.admin.authorization.runtime.activation.domain.po");
        factory.setJpaPropertyMap(Map.of("hibernate.hbm2ddl.auto", "none", "hibernate.default_schema", schema, "hibernate.show_sql", false));
        factory.afterPropertiesSet();
        entityManager = factory.getObject().createEntityManager();
        activations = new PermissionCatalogActivationRepository(entityManager, json);
    }

    private SourceImportRequest register() {
        return transaction(() -> {
            var plan = plans.plan(new ManifestRegistrationRequest.Plan(SCOPE, manifest(), "0", "0"), authority);
            registrations.register(new ManifestRegistrationRequest.Apply(SCOPE, "api", plan.planId(), OPERATION, plan.digests(), "0", "0"), authority);
            return manifests.sourceImport(SCOPE, "api", 1);
        });
    }


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
