package top.egon.cola.platform.tianquan.jianshen.admin.registration.catalog.service;

import top.egon.cola.platform.tianquan.jianshen.admin.registration.catalog.repository.CatalogAdministrationGuard;

import jakarta.persistence.EntityManager;
import jakarta.persistence.Query;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import top.egon.cola.platform.tianquan.jianshen.admin.authorization.runtime.state.domain.po.TenantAuthorizationStatePO;
import top.egon.cola.platform.tianquan.jianshen.admin.authorization.runtime.state.repository.TenantAuthorizationStateRepository;
import top.egon.cola.platform.tianquan.jianshen.admin.registration.catalog.repository.PermissionCatalogScopeRepository;
import top.egon.cola.platform.tianquan.jianshen.contract.authorization.SystemAuthorizationSnapshot;
import top.egon.cola.platform.tianquan.jianshen.core.rule.Rbac3RuleViolation;
import top.egon.cola.platform.tianquan.jianshen.starter.security.Rbac3UserDetails;
import top.egon.cola.platform.tianquan.shoubing.contract.IdentityPrincipal;

import java.util.List;

import static org.junit.jupiter.api.Assertions.*;
import static org.mockito.ArgumentMatchers.*;
import static org.mockito.Mockito.*;
import static top.egon.cola.platform.tianquan.jianshen.admin.registration.catalog.service.PermissionCatalogFixture.*;

class CatalogAdministrationGuardTest {
    private final PermissionCatalogScopeRepository scopes = mock(PermissionCatalogScopeRepository.class);
    private final TenantAuthorizationStateRepository policy = mock(TenantAuthorizationStateRepository.class);
    private final EntityManager entityManager = mock(EntityManager.class);
    private final Query query = mock(Query.class, RETURNS_SELF);
    private final Query policyFence = mock(Query.class, RETURNS_SELF);
    private final Query userFence = mock(Query.class, RETURNS_SELF);
    private final Rbac3UserDetails actor = mock(Rbac3UserDetails.class);
    private final IdentityPrincipal identity = mock(IdentityPrincipal.class);
    private final SystemAuthorizationSnapshot snapshot = mock(SystemAuthorizationSnapshot.class);
    private final CatalogAdministrationGuard guard = new CatalogAdministrationGuard(scopes, policy, entityManager);

    @BeforeEach
    void prepare() {
        when(actor.tenantId()).thenReturn("10");
        when(actor.rbac3UserId()).thenReturn("90");
        when(actor.identitySub()).thenReturn("9001");
        when(actor.identity()).thenReturn(identity);
        when(actor.snapshot()).thenReturn(snapshot);
        when(actor.hasPermission("manage")).thenReturn(true);
        when(identity.expiresAt()).thenReturn(NOW.plusSeconds(60));
        when(snapshot.expiresAt()).thenReturn(NOW.plusSeconds(30));
        when(scopes.lockScope(SCOPE)).thenReturn(new PermissionCatalogScopeRepository.ScopeState(SCOPE, 20, 1, 0));
        when(entityManager.createNativeQuery(anyString())).thenAnswer(call -> {
            String sql = call.getArgument(0);
            if (sql.contains("update rbac3_tenant_authorization_state")) return policyFence;
            if (sql.contains("update rbac3_user")) return userFence;
            return query;
        });
        when(policyFence.executeUpdate()).thenReturn(1);
        when(userFence.executeUpdate()).thenReturn(1);
        when(query.getResultList()).thenReturn(List.of(0L));
    }

    @Test
    void sameLocalTransactionFencesScopeThenTenantThenBoundUser() {
        assertEquals(20, guard.require(SCOPE, actor, "manage", NOW).applicationId());
        var order = inOrder(scopes, entityManager);
        order.verify(scopes).lockScope(SCOPE);
        order.verify(entityManager).createNativeQuery(contains("update rbac3_tenant_authorization_state"));
        order.verify(entityManager).createNativeQuery(contains("update rbac3_user"));
        verify(policyFence).setParameter("policy", 0L);
        verify(userFence).setParameter("subject", "9001");
        verify(userFence).setParameter("tenant", 10L);
        verify(userFence).setParameter("user", 90L);
        verify(userFence).setParameter("version", 0L);
        verify(policy, never()).requireForUpdate(anyLong());
        var sql = org.mockito.ArgumentCaptor.forClass(String.class);
        verify(entityManager, times(2)).createNativeQuery(sql.capture());
        assertTrue(sql.getAllValues().stream().allMatch(value -> value.toLowerCase(java.util.Locale.ROOT)
                .startsWith("update ") && !value.toLowerCase(java.util.Locale.ROOT).contains("for update")));
        var parser = new org.apache.shardingsphere.infra.parser.ShardingSphereSQLParserEngine(
                org.apache.shardingsphere.infra.spi.type.typed.TypedSPILoader.getService(
                        org.apache.shardingsphere.database.connector.core.type.DatabaseType.class, "PostgreSQL"),
                new org.apache.shardingsphere.sql.parser.engine.api.CacheOption(16, 64),
                new org.apache.shardingsphere.sql.parser.engine.api.CacheOption(16, 64));
        sql.getAllValues().forEach(value -> assertNotNull(parser.parse(value.replaceAll(":\\w+", "?"), false)));
    }

    @Test
    void readGuardChecksTheSameScopeAndVersionsWithoutLocking() {
        when(scopes.readScope(SCOPE)).thenReturn(new PermissionCatalogScopeRepository.ScopeState(SCOPE, 20, 1, 0));
        when(policy.require(10L)).thenReturn(new TenantAuthorizationStatePO(10L, "test", NOW));

        assertEquals(20, guard.requireRead(SCOPE, actor, "manage", NOW).applicationId());

        verify(policy, never()).requireForUpdate(anyLong());
        verify(scopes, never()).lockScope(any());
        var sql = org.mockito.ArgumentCaptor.forClass(String.class);
        verify(entityManager).createNativeQuery(sql.capture());
        assertFalse(sql.getValue().toLowerCase(java.util.Locale.ROOT).contains("for update"));
        verify(query).setParameter("tenant", 10L);
        verify(query).setParameter("subject", "9001");
        when(query.getResultList()).thenReturn(List.of(1L));
        assertEquals("AUTH_SNAPSHOT_NOT_READY", assertThrows(Rbac3RuleViolation.class,
                () -> guard.requireRead(SCOPE, actor, "manage", NOW)).reasonCode());
    }

    @Test
    void crossTenantMissingCapabilityAndExpiredSnapshotStopBeforeDatabase() {
        when(actor.tenantId()).thenReturn("11");
        assertThrows(Rbac3RuleViolation.class, () -> guard.require(SCOPE, actor, "manage", NOW));
        when(actor.tenantId()).thenReturn("10");
        when(actor.hasPermission("manage")).thenReturn(false);
        assertThrows(Rbac3RuleViolation.class, () -> guard.require(SCOPE, actor, "manage", NOW));
        when(actor.hasPermission("manage")).thenReturn(true);
        when(snapshot.expiresAt()).thenReturn(NOW);
        assertThrows(Rbac3RuleViolation.class, () -> guard.require(SCOPE, actor, "manage", NOW));
        verifyNoInteractions(scopes, policy, entityManager);
    }

    @Test
    void revocationFenceRejectsStalePolicyOrUserVersion() {
        when(policyFence.executeUpdate()).thenReturn(0);
        assertEquals("AUTH_SNAPSHOT_NOT_READY", assertThrows(Rbac3RuleViolation.class, () -> guard.require(SCOPE, actor, "manage", NOW)).reasonCode());
        verify(userFence, never()).executeUpdate();
        when(policyFence.executeUpdate()).thenReturn(1);
        when(userFence.executeUpdate()).thenReturn(0);
        assertEquals("AUTH_SNAPSHOT_NOT_READY", assertThrows(Rbac3RuleViolation.class, () -> guard.require(SCOPE, actor, "manage", NOW)).reasonCode());
    }

    @Test
    void failedUserFenceRollsBackTheOwningTransaction() {
        when(userFence.executeUpdate()).thenReturn(0);
        var transactions = mock(org.springframework.transaction.PlatformTransactionManager.class);
        when(transactions.getTransaction(any())).thenReturn(new org.springframework.transaction.support.SimpleTransactionStatus());
        var transaction = new org.springframework.transaction.support.TransactionTemplate(transactions);

        assertThrows(Rbac3RuleViolation.class, () -> transaction.executeWithoutResult(
                status -> guard.require(SCOPE, actor, "manage", NOW)));
        verify(policyFence).executeUpdate();
        verify(transactions).rollback(any());
    }
}
