package top.egon.cola.platform.tianquan.jianshen.admin.registration.catalog.repository;

import jakarta.persistence.EntityManager;
import jakarta.persistence.Query;
import java.net.URI;
import java.time.Instant;
import java.util.List;
import java.util.Locale;
import java.util.Set;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.springframework.transaction.PlatformTransactionManager;
import org.springframework.transaction.support.SimpleTransactionStatus;
import org.springframework.transaction.support.TransactionTemplate;
import top.egon.cola.platform.tianquan.jianshen.admin.registration.catalog.domain.convertor.PermissionCatalogJson;
import top.egon.cola.platform.tianquan.jianshen.admin.registration.catalog.domain.PermissionCatalogCaller;
import top.egon.cola.platform.tianquan.jianshen.contract.permission.CatalogScope;
import top.egon.cola.platform.tianquan.jianshen.core.rule.Rbac3RuleViolation;
import top.egon.cola.platform.tianquan.shoubing.contract.ServiceIdentityPrincipal;
import top.egon.cola.platform.tianquan.shoubing.contract.ServiceTokenContext;

import static org.junit.jupiter.api.Assertions.*;
import static org.mockito.ArgumentMatchers.*;
import static org.mockito.Mockito.*;

class PermissionCatalogScopeReplicaFenceTest {
    private final EntityManager entities = mock(EntityManager.class);
    private final Query scopeRead = mock(Query.class, RETURNS_SELF);
    private final Query scopeFence = mock(Query.class, RETURNS_SELF);
    private final Query bindingFence = mock(Query.class, RETURNS_SELF);
    private final Query pointerRead = mock(Query.class, RETURNS_SELF);
    private final Query pointerFence = mock(Query.class, RETURNS_SELF);
    private final Query ownerRead = mock(Query.class, RETURNS_SELF);
    private final Query ownerFence = mock(Query.class, RETURNS_SELF);
    private final Query grantRead = mock(Query.class, RETURNS_SELF);
    private final Query grantFence = mock(Query.class, RETURNS_SELF);
    private final PermissionCatalogJson json = mock(PermissionCatalogJson.class);
    private final CatalogScope target = new CatalogScope("42", "101", "business", "application", "namespace", "prod");
    private final PermissionCatalogScopeRepository repository = new PermissionCatalogScopeRepository(entities, json);

    @BeforeEach
    void setUp() {
        when(entities.createNativeQuery(anyString())).thenAnswer(invocation -> {
            String sql = invocation.<String>getArgument(0).toLowerCase(Locale.ROOT);
            if (sql.contains("select s.id")) return scopeRead;
            if (sql.contains("update rbac3_catalog_scope s set")) {
                if (sql.contains("from rbac3_application")) return bindingFence;
                if (sql.contains("from rbac3_catalog_active_pointer")) return pointerFence;
                if (sql.contains("from rbac3_catalog_producer")) return ownerFence;
                if (sql.contains("from rbac3_catalog_service_grant")) return grantFence;
            }
            if (sql.contains("update rbac3_catalog_scope")) return scopeFence;
            if (sql.contains("select revision, policy_version")) return pointerRead;
            if (sql.contains("select kind, owned_key_prefixes")) return ownerRead;
            if (sql.contains("select id, version, capabilities")) return grantRead;
            throw new AssertionError("Unexpected SQL: " + sql);
        });
        when(scopeRead.getResultList()).thenReturn(List.of((Object) new Object[]{42L, 101L, "business", "application", "namespace", "prod", 71L}));
        when(pointerRead.getResultList()).thenReturn(List.of((Object) new Object[]{3L, 7L}));
        when(ownerRead.getResultList()).thenReturn(List.of((Object) new Object[]{"JAVA", "[]", "[]", "[]", "[]", 4L, 5L}));
        when(grantRead.getResultList()).thenReturn(List.of((Object) new Object[]{81L, 6L, "capabilities", "[]", true}));
        when(json.strings(anyString())).thenReturn(List.of());
        when(json.strings("capabilities")).thenReturn(List.of("REGISTER"));
        when(scopeFence.executeUpdate()).thenReturn(1);
        when(bindingFence.executeUpdate()).thenReturn(1);
        when(pointerFence.executeUpdate()).thenReturn(1);
        when(ownerFence.executeUpdate()).thenReturn(1);
        when(grantFence.executeUpdate()).thenReturn(1);
    }

    @Test
    void commandReadsScopeWithoutLockThenFencesItBeforeCheckingThePointer() {
        var result = repository.lockScope(target);
        assertEquals(71L, result.applicationId());
        assertEquals(3L, result.activeRevision());
        var order = inOrder(entities);
        order.verify(entities).createNativeQuery(contains("select s.id"));
        order.verify(entities).createNativeQuery(contains("update rbac3_catalog_scope set"));
        order.verify(entities).createNativeQuery(contains("update rbac3_catalog_scope s set"));
        order.verify(entities).createNativeQuery(contains("select revision, policy_version"));
        order.verify(entities).createNativeQuery(contains("from rbac3_catalog_active_pointer p"));
        verify(scopeFence).setParameter("tenant", 101L);
        verify(bindingFence).setParameter("tenant", 101L);
        var captured = org.mockito.ArgumentCaptor.forClass(String.class);
        verify(entities, times(5)).createNativeQuery(captured.capture());
        assertFalse(captured.getAllValues().getFirst().toLowerCase(Locale.ROOT).contains("for update"));
        assertTrue(captured.getAllValues().get(2).contains("exists (select 1 from rbac3_application"));
        assertFalse(captured.getAllValues().get(3).toLowerCase(Locale.ROOT).contains("for update"));
        var parser = new org.apache.shardingsphere.infra.parser.ShardingSphereSQLParserEngine(
                org.apache.shardingsphere.infra.spi.type.typed.TypedSPILoader.getService(
                        org.apache.shardingsphere.database.connector.core.type.DatabaseType.class, "PostgreSQL"),
                new org.apache.shardingsphere.sql.parser.engine.api.CacheOption(16, 64),
                new org.apache.shardingsphere.sql.parser.engine.api.CacheOption(16, 64));
        for (int index : List.of(1, 2, 4)) {
            assertNotNull(parser.parse(captured.getAllValues().get(index).replaceAll(":\\w+", "?"), false));
        }
    }

    @Test
    void disabledPrimaryBindingRollsBackTheFirstFenceAndDoesNotReadThePointer() {
        when(bindingFence.executeUpdate()).thenReturn(0);
        var manager = mock(PlatformTransactionManager.class);
        when(manager.getTransaction(any())).thenReturn(new SimpleTransactionStatus());

        var error = assertThrows(Rbac3RuleViolation.class,
                () -> new TransactionTemplate(manager).execute(status -> repository.lockScope(target)));
        assertEquals("APPLICATION_BINDING_DENIED", error.reasonCode());
        verify(manager).rollback(any());
        verifyNoInteractions(pointerRead);
    }

    @Test
    void readOnlyScopeQueryDoesNotWriteOrUseALock() {
        assertEquals(3L, repository.readScope(target).activeRevision());
        verifyNoInteractions(scopeFence, bindingFence);
        var captured = org.mockito.ArgumentCaptor.forClass(String.class);
        verify(entities, times(2)).createNativeQuery(captured.capture());
        assertTrue(captured.getAllValues().stream().noneMatch(sql -> sql.toLowerCase(Locale.ROOT).contains("for update")));
    }

    @Test
    void repeatedScopeFencesInOneTransactionDoNotDependOnReplicaSeeingTheirOwnWrites() {
        repository.lockScope(target);
        repository.lockScope(target);
        verify(scopeFence, times(2)).executeUpdate();
        verify(bindingFence, times(2)).executeUpdate();
        verify(pointerFence, times(2)).executeUpdate();
    }

    @Test
    void stalePointerRollsBackBeforeReturningAWriteScope() {
        when(pointerFence.executeUpdate()).thenReturn(0);
        var manager = mock(PlatformTransactionManager.class);
        when(manager.getTransaction(any())).thenReturn(new SimpleTransactionStatus());
        var failure = assertThrows(Rbac3RuleViolation.class,
                () -> new TransactionTemplate(manager).execute(status -> repository.lockScope(target)));
        assertEquals("AUTH_SNAPSHOT_NOT_READY", failure.reasonCode());
        verify(manager).rollback(any());
    }

    @Test
    void staleProducerOrGrantCannotAuthorizeAMutation() {
        var caller = caller();
        when(ownerFence.executeUpdate()).thenReturn(0);
        assertEquals("SERVICE_IDENTITY_DENIED", assertThrows(Rbac3RuleViolation.class,
                () -> repository.authorize(target, "producer", caller, PermissionCatalogCaller.Capability.REGISTER, NOW)).reasonCode());
        verifyNoInteractions(grantRead);
        when(ownerFence.executeUpdate()).thenReturn(1);
        when(grantFence.executeUpdate()).thenReturn(0);
        assertEquals("SERVICE_IDENTITY_DENIED", assertThrows(Rbac3RuleViolation.class,
                () -> repository.authorize(target, "producer", caller, PermissionCatalogCaller.Capability.REGISTER, NOW)).reasonCode());
        verify(grantFence).setParameter("version", 6L);
        var captured = org.mockito.ArgumentCaptor.forClass(String.class);
        verify(entities, atLeastOnce()).createNativeQuery(captured.capture());
        assertTrue(captured.getAllValues().stream().filter(sql -> sql.trim().toLowerCase(Locale.ROOT).startsWith("select"))
                .noneMatch(sql -> sql.toLowerCase(Locale.ROOT).contains("for update") || sql.toLowerCase(Locale.ROOT).contains("for share")));
    }

    private static final Instant NOW = Instant.parse("2026-10-28T00:00:00Z");

    private PermissionCatalogCaller caller() {
        return new PermissionCatalogCaller(URI.create("https://issuer.example/tenants/101"), new ServiceIdentityPrincipal(
                "pipeline", "101", "pipeline", "token", URI.create("https://rbac.example"), 1,
                Set.of(PermissionCatalogCaller.Capability.REGISTER.scope()), "infra", "publisher", "test", "credential",
                NOW.minusSeconds(1), NOW.plusSeconds(3600), "pipeline-app", ServiceTokenContext.TENANT));
    }
}
