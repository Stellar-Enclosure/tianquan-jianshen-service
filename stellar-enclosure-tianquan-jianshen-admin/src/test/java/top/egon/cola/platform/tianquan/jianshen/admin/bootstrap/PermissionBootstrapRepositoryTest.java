package top.egon.cola.platform.tianquan.jianshen.admin.bootstrap;

import jakarta.persistence.EntityManager;
import jakarta.persistence.Query;
import jakarta.persistence.TypedQuery;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;
import top.egon.cola.component.common.id.snowflake.SnowflakeIdGenerator;
import top.egon.cola.platform.tianquan.jianshen.admin.authorization.grant.application.domain.enums.TenantApplicationStatusEnum;
import top.egon.cola.platform.tianquan.jianshen.admin.authorization.grant.application.domain.po.TenantApplicationPO;
import top.egon.cola.platform.tianquan.jianshen.admin.authorization.grant.business.domain.po.UserBusinessAccessPO;
import top.egon.cola.platform.tianquan.jianshen.admin.authorization.grant.userrole.domain.po.UserRoleAssignmentPO;
import top.egon.cola.platform.tianquan.jianshen.admin.authorization.runtime.activation.domain.po.UserActiveRolePO;
import top.egon.cola.platform.tianquan.jianshen.admin.bootstrap.controller.cli.PermissionBootstrapCli;
import top.egon.cola.platform.tianquan.jianshen.admin.bootstrap.domain.dto.PermissionAdministratorBootstrapCommandDTO;
import top.egon.cola.platform.tianquan.jianshen.admin.bootstrap.domain.dto.PermissionCatalogBootstrapCommandDTO;
import top.egon.cola.platform.tianquan.jianshen.admin.bootstrap.domain.vo.PermissionBootstrapReceiptVO;
import top.egon.cola.platform.tianquan.jianshen.admin.bootstrap.repository.PermissionBootstrapRepository;
import top.egon.cola.platform.tianquan.jianshen.admin.iam.role.domain.po.RolePO;
import top.egon.cola.platform.tianquan.jianshen.admin.iam.user.domain.enums.UserStatusEnum;
import top.egon.cola.platform.tianquan.jianshen.admin.iam.user.domain.po.UserPO;
import top.egon.cola.platform.tianquan.jianshen.admin.registration.catalog.domain.PermissionCatalogCaller;
import top.egon.cola.platform.tianquan.jianshen.admin.registration.catalog.domain.convertor.PermissionCatalogJson;
import top.egon.cola.platform.tianquan.jianshen.admin.registration.catalog.repository.PermissionCatalogScopeRepository;
import top.egon.cola.platform.tianquan.jianshen.contract.permission.CatalogScope;
import top.egon.cola.platform.tianquan.jianshen.contract.permission.PermissionManifest;

import java.net.URI;
import java.time.Duration;
import java.time.Instant;
import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;

import static org.assertj.core.api.Assertions.*;
import static org.mockito.ArgumentMatchers.*;
import static org.mockito.Mockito.*;

/** Exercises the persistence owner with a controlled transport; no PostgreSQL is opened. */
class PermissionBootstrapRepositoryTest {
    private static final Instant NOW = Instant.parse("2026-10-25T00:00:00Z");
    private static final CatalogScope TARGET = new CatalogScope("1", "10", "xingyuan", "rbac", "default", "test");
    private static final String OPERATION = "00000000-0000-0000-0000-000000000001";
    private static final PermissionCatalogScopeRepository.ScopeState ACTIVE = new PermissionCatalogScopeRepository.ScopeState(TARGET, 20, 1, 1);

    @BeforeAll
    static void idEngine() { SnowflakeIdGenerator.initialize(0L, Duration.ofMillis(5)); }

    @Test
    void b0WritesOnlySourceAuthorityAndNeverResourcePermissionRoleOrUserRows() {
        var fixture = new Fixture();
        assertThat(fixture.repository.initializeCatalog(catalog(), NOW)).hasSize(1);
        assertThat(fixture.updates).hasSize(6).allMatch(sql -> sql.startsWith("insert into rbac3_tenant_authorization_state")
                || sql.startsWith("insert into rbac3_application(") || sql.startsWith("insert into rbac3_catalog_scope(")
                || sql.startsWith("insert into rbac3_catalog_active_pointer(") || sql.startsWith("insert into rbac3_catalog_producer(")
                || sql.startsWith("insert into rbac3_catalog_service_grant("));
        verify(fixture.manager, never()).persist(any());
    }

    @Test
    void b0RejectsDisabledOwnersAndConflictingPrefixesWithoutReenablingThem() {
        var fixture = new Fixture();
        fixture.rows.put("from rbac3_catalog_producer", List.<Object[]>of(new Object[]{"r-java", "JAVA", "[\"r.api.\"]", "[\"system:\"]", "[\"permission/\"]", "[\"admin\"]", 0L, false, 0L}));
        assertThatThrownBy(() -> fixture.repository.initializeCatalog(catalog(), NOW)).hasMessage("BOOTSTRAP_PRODUCER_CONFLICT");
        assertThat(fixture.updates).noneMatch(sql -> sql.contains("insert into rbac3_catalog_producer") || sql.startsWith("update "));
        fixture.rows.put("from rbac3_catalog_producer", List.<Object[]>of(new Object[]{"foreign-java", "JAVA", "[\"r.\"]", "[]", "[]", "[\"other\"]", 0L, true, 0L}));
        assertThatThrownBy(() -> fixture.repository.initializeCatalog(catalog(), NOW)).hasMessage("BOOTSTRAP_OWNER_PREFIX_CONFLICT");
    }

    @Test
    void b0RejectsOverlappingUnderscorePermissionOwnersIgnoringCase() {
        var fixture = new Fixture();
        var baseline = catalog();
        var original = baseline.producers().getFirst();
        var producer = new PermissionCatalogBootstrapCommandDTO.Producer(original.producerId(), original.kind(),
                original.ownedKeyPrefixes(), List.of("TIANSHU_"), original.ownedMessagePrefixes(), original.expectedModules(), original.serviceGrants());
        var command = new PermissionCatalogBootstrapCommandDTO(baseline.schemaVersion(), baseline.operationId(), baseline.connectionFile(),
                baseline.target(), baseline.applicationId(), baseline.applicationName(), baseline.ddcBusinessId(), baseline.ddcApplicationId(), List.of(producer));
        fixture.rows.put("from rbac3_catalog_producer", List.<Object[]>of(new Object[]{"foreign-java", "JAVA", "[\"foreign.api.\"]",
                "[\"tianshu_ai_\"]", "[\"foreign/\"]", "[\"other\"]", 0L, true, 0L}));

        assertThatThrownBy(() -> fixture.repository.initializeCatalog(command, NOW)).hasMessage("BOOTSTRAP_OWNER_PREFIX_CONFLICT");
        assertThat(fixture.updates).noneMatch(sql -> sql.contains("insert into rbac3_catalog_producer") || sql.startsWith("update "));
    }

    @Test
    void b0RejectsActiveCatalogAndNeverOverwritesOrReenablesServiceGrants() {
        var fixture = new Fixture(); fixture.revision = 1;
        assertThatThrownBy(() -> fixture.repository.initializeCatalog(catalog(), NOW)).hasMessage("BOOTSTRAP_CATALOG_ALREADY_ACTIVE");
        fixture.revision = 0;
        fixture.rows.put("from rbac3_catalog_service_grant", List.<Object[]>of(new Object[]{30L, "https://idp.example/tenants/10", "ci", "https://rbac.example",
                "[\"REGISTER\"]", "[\"refs/heads/main\"]", false, false, 0L}));
        assertThatThrownBy(() -> fixture.repository.initializeCatalog(catalog(), NOW)).hasMessage("BOOTSTRAP_SERVICE_GRANT_CONFLICT");
        assertThat(fixture.updates).noneMatch(sql -> sql.contains("insert into rbac3_catalog_service_grant") || sql.startsWith("update "));
    }

    @Test
    void originalAuditReturnsTheExactReceiptAndRejectsChangedOperationContent() {
        var fixture = new Fixture();
        var receipt = new PermissionBootstrapReceiptVO(1, "B0", OPERATION, "a".repeat(64), TARGET, "20", "30", "40", List.of("r-java"), Map.of(), NOW);
        fixture.rows.put("from rbac3_audit_log", List.<Object[]>of(new Object[]{"a".repeat(64), fixture.json.write(receipt)}));
        assertThat(fixture.repository.original("10", OPERATION, "a".repeat(64))).contains(receipt);
        assertThatThrownBy(() -> fixture.repository.original("10", OPERATION, "b".repeat(64))).hasMessage("BOOTSTRAP_OPERATION_CONFLICT");
        assertThat(fixture.updates).isEmpty();
    }

    @Test
    void b1RequiresAllCurrentActiveProducersToHaveMatchingQualifiedReadyBuilds() {
        var fixture = new Fixture();
        assertThatThrownBy(() -> fixture.repository.requireQualifiedActiveCatalog(ACTIVE)).hasMessage("BOOTSTRAP_ACTIVE_QUALIFICATION_MISSING");
        fixture.rows.put("select a.producer_count", List.<Object[]>of(new Object[]{2, 1L}));
        assertThatThrownBy(() -> fixture.repository.requireQualifiedActiveCatalog(ACTIVE)).hasMessage("BOOTSTRAP_ACTIVE_QUALIFICATION_MISSING");
        fixture.rows.put("select a.producer_count", List.<Object[]>of(new Object[]{2, 2L}));
        assertThatCode(() -> fixture.repository.requireQualifiedActiveCatalog(ACTIVE)).doesNotThrowAnyException();
        assertThat(fixture.queries.getFirst()).contains("owner.enabled", "manifest.state='READY'", "proof.id=member.qualification_id",
                "proof.commit=manifest.commit", "proof.build_id=manifest.build_id", "proof.expires_at>a.created_at", "head.revision=:revision");
    }

    @Test
    void newAdministratorHasOneFreshRoleSelfClosureDirectAssignmentAndOptionalActivation() {
        var fixture = new Fixture();
        var administrator = fixture.repository.initializeAdministrator(ACTIVE, administrator(true), NOW, NOW);
        var role = fixture.persisted.stream().filter(RolePO.class::isInstance).map(RolePO.class::cast).findFirst().orElseThrow();
        var assignment = fixture.persisted.stream().filter(UserRoleAssignmentPO.class::isInstance).map(UserRoleAssignmentPO.class::cast).findFirst().orElseThrow();
        var active = fixture.persisted.stream().filter(UserActiveRolePO.class::isInstance).map(UserActiveRolePO.class::cast).findFirst().orElseThrow();
        assertThat(administrator.authVersion()).isEqualTo(1);
        assertThat(role.getApplicationId()).isEqualTo(20L);
        assertThat(assignment.getRoleId()).isEqualTo(role.getId());
        assertThat(assignment.getAssignmentType().name()).isEqualTo("DIRECT");
        assertThat(active.getRootRoleId()).isEqualTo(role.getId());
        assertThat(active.getEligibleAssignmentIds()).containsExactly(assignment.getId().toString());
        assertThat(fixture.updates).singleElement().asString().startsWith("insert into rbac3_role_closure");
        assertThat(fixture.queries).anySatisfy(sql -> assertThat(sql).contains("rbac3_user_active_role", "application_id=:application"));
        assertThat(fixture.updates).noneMatch(sql -> sql.startsWith("delete ") || sql.startsWith("update "));
    }

    @Test
    void existingUserAndOtherApplicationRolesArePreservedWhenActivationIsNotRequested() {
        var fixture = new Fixture();
        var user = new UserPO(90L, 10L, "subject", UserStatusEnum.ACTIVE, "original", NOW.minusSeconds(60));
        user.incrementAuthVersion("original", NOW.minusSeconds(60));
        fixture.users = List.of(user);
        var result = fixture.repository.initializeAdministrator(ACTIVE, administrator(false), NOW, NOW);
        assertThat(result.userId()).isEqualTo(90L); assertThat(result.authVersion()).isEqualTo(2);
        assertThat(fixture.persisted).noneMatch(value -> value instanceof UserPO || value instanceof UserActiveRolePO);
        assertThat(fixture.queries).noneMatch(sql -> sql.contains("rbac3_user_active_role"));
    }

    @Test
    void multipleBusinessSourcesRetainTheirIndependentRevocationsAndEffectiveAccess() {
        var fixture = new Fixture();
        var revoked = new UserBusinessAccessPO(80L, 10L, 90L, "30", NOW.minusSeconds(60), null, "MANUAL", "old", "old", null, "original", NOW);
        revoked.revoke("original", NOW);
        var active = new UserBusinessAccessPO(81L, 10L, 90L, "30", NOW.minusSeconds(60), null, "SYSTEM", "current", "current", null, "original", NOW);
        fixture.users = List.of(new UserPO(90L, 10L, "subject", UserStatusEnum.ACTIVE, "original", NOW));
        fixture.businesses = List.of(revoked, active);
        assertThatCode(() -> fixture.repository.initializeAdministrator(ACTIVE, administrator(false), NOW, NOW)).doesNotThrowAnyException();
        assertThat(revoked.getStatus().name()).isEqualTo("REVOKED");
        assertThat(active.isEffective(NOW)).isTrue();
        assertThat(fixture.persisted).noneMatch(UserBusinessAccessPO.class::isInstance);
        fixture.businesses = List.of(revoked);
        assertThatThrownBy(() -> fixture.repository.initializeAdministrator(ACTIVE, administrator(false), NOW, NOW)).hasMessage("BOOTSTRAP_BUSINESS_ENTITLEMENT_CONFLICT");
    }

    @Test
    void bootstrapStatementsParseWithTheActualNativePostgresqlDialect() {
        var fixture = new Fixture();
        fixture.repository.lockTenant("10");
        fixture.repository.original("10", OPERATION, "a".repeat(64));
        fixture.repository.initializeCatalog(catalog(), NOW);
        fixture.rows.put("select a.producer_count", List.<Object[]>of(new Object[]{1, 1L}));
        fixture.repository.requireQualifiedActiveCatalog(ACTIVE);
        fixture.repository.initializeAdministrator(ACTIVE, administrator(true), NOW, NOW);
        var parser = new org.apache.shardingsphere.infra.parser.ShardingSphereSQLParserEngine(
                org.apache.shardingsphere.infra.spi.type.typed.TypedSPILoader.getService(
                        org.apache.shardingsphere.database.connector.core.type.DatabaseType.class, "PostgreSQL"),
                new org.apache.shardingsphere.sql.parser.engine.api.CacheOption(16, 64),
                new org.apache.shardingsphere.sql.parser.engine.api.CacheOption(16, 64));
        assertThat(fixture.queries).allSatisfy(sql -> assertThat(parser.parse(sql.replaceAll(":\\w+", "?"), false)).isNotNull());
    }

    @Test
    void disabledIdentityRevokedEntitlementAndExistingCurrentApplicationActivationAreNotRepaired() {
        var fixture = new Fixture();
        fixture.users = List.of(new UserPO(90L, 10L, "subject", UserStatusEnum.DISABLED, "original", NOW));
        assertThatThrownBy(() -> fixture.repository.initializeAdministrator(ACTIVE, administrator(true), NOW, NOW)).hasMessage("BOOTSTRAP_USER_DISABLED");
        assertThat(fixture.persisted).isEmpty();
        fixture.users = List.of(new UserPO(90L, 10L, "subject", UserStatusEnum.ACTIVE, "original", NOW));
        fixture.applications = List.of(new TenantApplicationPO(80L, 10L, 20L, TenantApplicationStatusEnum.REVOKED, NOW, null, "SYSTEM", "old", "revoked", null, "original", NOW));
        assertThatThrownBy(() -> fixture.repository.initializeAdministrator(ACTIVE, administrator(true), NOW, NOW)).hasMessage("BOOTSTRAP_APPLICATION_ENTITLEMENT_CONFLICT");
        fixture.applications = List.of(); fixture.activeCount = 1;
        assertThatThrownBy(() -> fixture.repository.initializeAdministrator(ACTIVE, administrator(true), NOW, NOW)).hasMessage("BOOTSTRAP_ACTIVE_ROLE_ALREADY_EXISTS");
        assertThat(fixture.persisted).noneMatch(value -> value instanceof RolePO || value instanceof UserActiveRolePO || value instanceof UserRoleAssignmentPO);
    }

    private static PermissionCatalogBootstrapCommandDTO catalog() {
        var grant = new PermissionCatalogBootstrapCommandDTO.ServiceGrant(URI.create("https://idp.example/tenants/10"), "ci", URI.create("https://rbac.example"),
                List.of(PermissionCatalogCaller.Capability.REGISTER), List.of("refs/heads/main"), false);
        var owner = new PermissionCatalogBootstrapCommandDTO.Producer("r-java", PermissionManifest.ProducerKind.JAVA,
                List.of("r.api."), List.of("system:"), List.of("permission/"), List.of("admin"), List.of(grant));
        return new PermissionCatalogBootstrapCommandDTO(1, OPERATION, "/private/connection.json", TARGET, "20", "RBAC", "30", "40", List.of(owner));
    }

    private static PermissionAdministratorBootstrapCommandDTO administrator(boolean activate) {
        return new PermissionAdministratorBootstrapCommandDTO(1, OPERATION, "/private/connection.json", TARGET, "1", "subject", "BOOTSTRAP_ADMIN",
                "Initial administrator", List.of("system:role:read"), null, null, activate);
    }

    private static final class Fixture {
        final EntityManager manager = mock(EntityManager.class);
        final PermissionCatalogJson json = new PermissionCatalogJson(PermissionBootstrapCli.mapper());
        final PermissionBootstrapRepository repository = new PermissionBootstrapRepository(manager, json);
        final Map<String, List<?>> rows = new LinkedHashMap<>();
        final List<String> queries = new ArrayList<>(); final List<String> updates = new ArrayList<>(); final List<Object> persisted = new ArrayList<>();
        List<UserPO> users = List.of(); List<TenantApplicationPO> applications = List.of(); List<UserBusinessAccessPO> businesses = List.of();
        long revision; long activeCount;

        Fixture() {
            when(manager.createNativeQuery(anyString())).thenAnswer(call -> {
                String sql = call.getArgument(0); queries.add(sql);
                var query = mock(Query.class); when(query.setParameter(anyString(), any())).thenReturn(query);
                when(query.getResultList()).thenAnswer(ignored -> rows.entrySet().stream().filter(entry -> sql.contains(entry.getKey())).map(Map.Entry::getValue).findFirst().orElse(List.of()));
                when(query.getSingleResult()).thenAnswer(ignored -> sql.startsWith("select revision") ? revision
                        : sql.startsWith("select application_id") ? new Object[]{20L, "30", "40"} : activeCount);
                when(query.executeUpdate()).thenAnswer(ignored -> { updates.add(sql.stripLeading()); return 1; });
                return query;
            });
            when(manager.createQuery(anyString(), eq(UserPO.class))).thenAnswer(call -> typed(users));
            when(manager.createQuery(anyString(), eq(TenantApplicationPO.class))).thenAnswer(call -> typed(applications));
            when(manager.createQuery(anyString(), eq(UserBusinessAccessPO.class))).thenAnswer(call -> typed(businesses));
            doAnswer(call -> { persisted.add(call.getArgument(0)); return null; }).when(manager).persist(any());
        }

        private <T> TypedQuery<T> typed(List<T> values) {
            @SuppressWarnings("unchecked") TypedQuery<T> query = mock(TypedQuery.class);
            when(query.setParameter(anyString(), any())).thenReturn(query); when(query.setLockMode(any())).thenReturn(query);
            when(query.getResultList()).thenReturn(values); return query;
        }
    }
}
