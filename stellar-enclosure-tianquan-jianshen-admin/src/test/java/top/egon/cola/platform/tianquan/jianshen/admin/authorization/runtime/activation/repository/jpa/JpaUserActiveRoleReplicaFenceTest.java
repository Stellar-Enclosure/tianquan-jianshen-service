package top.egon.cola.platform.tianquan.jianshen.admin.authorization.runtime.activation.repository.jpa;

import jakarta.persistence.EntityManager;
import jakarta.persistence.Query;
import jakarta.persistence.TypedQuery;
import java.time.Instant;
import java.util.List;
import org.junit.jupiter.api.Test;
import top.egon.cola.platform.tianquan.jianshen.admin.authorization.runtime.activation.domain.po.UserActiveRolePO;
import top.egon.cola.platform.tianquan.jianshen.admin.iam.user.domain.po.UserPO;

import static org.assertj.core.api.Assertions.*;
import static org.mockito.ArgumentMatchers.*;
import static org.mockito.Mockito.*;

class JpaUserActiveRoleReplicaFenceTest {
    private static final Instant NOW = Instant.parse("2026-10-28T00:00:00Z");

    @Test
    void reselectionUsesReplicaCandidatesAndPrimaryConditionalFences() {
        var entities = mock(EntityManager.class);
        var user = mock(UserPO.class);
        when(user.getTenantId()).thenReturn(7L);
        when(user.getId()).thenReturn(9L);
        when(user.getVersion()).thenReturn(3L);
        when(user.getAuthVersion()).thenReturn(5L);
        @SuppressWarnings("unchecked") TypedQuery<UserPO> users = mock(TypedQuery.class, RETURNS_SELF);
        when(entities.createQuery(anyString(), eq(UserPO.class))).thenReturn(users);
        when(users.getSingleResultOrNull()).thenReturn(user);
        @SuppressWarnings("unchecked") TypedQuery<UserActiveRolePO> roles = mock(TypedQuery.class, RETURNS_SELF);
        when(entities.createQuery(anyString(), eq(UserActiveRolePO.class))).thenReturn(roles);
        var role = new UserActiveRolePO(7L, 9L, 11L, 13L, List.of("17"), NOW);
        when(roles.getResultList()).thenReturn(List.of(role));
        var update = mock(Query.class, RETURNS_SELF);
        when(entities.createNativeQuery(anyString())).thenReturn(update);
        when(update.executeUpdate()).thenReturn(1);

        new JpaUserActiveRoleRepository(entities).requireReselection("7", "9", 5L, NOW, "worker");

        verify(entities).remove(role);
        verify(user).incrementAuthVersion("worker", NOW);
        verify(users).setParameter("tenant", 7L);
        verify(users).setParameter("id", 9L);
        verify(entities, never()).find(eq(UserPO.class), any(), any(jakarta.persistence.LockModeType.class));
        var sql = org.mockito.ArgumentCaptor.forClass(String.class);
        verify(entities, times(2)).createNativeQuery(sql.capture());
        assertThat(sql.getAllValues()).allSatisfy(value -> assertThat(value.toLowerCase())
                .contains("tenant_id = :tenant", "version = :version").doesNotContain("for update", "for share"));
        assertThat(sql.getAllValues().getLast()).contains("count(*)", "application_id = :app0", "root_role_id = :role0");
        var parser = new org.apache.shardingsphere.infra.parser.ShardingSphereSQLParserEngine(
                org.apache.shardingsphere.infra.spi.type.typed.TypedSPILoader.getService(
                        org.apache.shardingsphere.database.connector.core.type.DatabaseType.class, "PostgreSQL"),
                new org.apache.shardingsphere.sql.parser.engine.api.CacheOption(16, 64),
                new org.apache.shardingsphere.sql.parser.engine.api.CacheOption(16, 64));
        assertThat(parser.parse(sql.getAllValues().getLast().replaceAll(":\\w+", "?"), false)).isNotNull();
    }

    @Test
    void missingOrChangedPrimaryRoleAbortsBeforeMutation() {
        var entities = mock(EntityManager.class);
        var user = mock(UserPO.class);
        when(user.getTenantId()).thenReturn(7L);
        when(user.getId()).thenReturn(9L);
        when(user.getVersion()).thenReturn(3L);
        when(user.getAuthVersion()).thenReturn(5L);
        @SuppressWarnings("unchecked") TypedQuery<UserPO> users = mock(TypedQuery.class, RETURNS_SELF);
        when(entities.createQuery(anyString(), eq(UserPO.class))).thenReturn(users);
        when(users.getSingleResultOrNull()).thenReturn(user);
        @SuppressWarnings("unchecked") TypedQuery<UserActiveRolePO> roles = mock(TypedQuery.class, RETURNS_SELF);
        when(entities.createQuery(anyString(), eq(UserActiveRolePO.class))).thenReturn(roles);
        when(roles.getResultList()).thenReturn(List.of());
        var update = mock(Query.class, RETURNS_SELF);
        when(entities.createNativeQuery(anyString())).thenReturn(update);
        when(update.executeUpdate()).thenReturn(1, 0);

        assertThatThrownBy(() -> new JpaUserActiveRoleRepository(entities).requireReselection("7", "9", 5L, NOW, "worker"))
                .isInstanceOf(org.springframework.dao.OptimisticLockingFailureException.class);
        verify(entities, never()).remove(any());
        verify(user, never()).incrementAuthVersion(anyString(), any());
    }

    @Test
    void invalidRootResolutionCanBeHandledInsideTheOwningTransaction() throws Exception {
        var method = JpaUserActiveRoleRepository.class.getMethod("replace",
                top.egon.cola.platform.tianquan.jianshen.admin.authorization.runtime.activation.domain.dto.ReplaceCommandDTO.class,
                Instant.class, java.util.function.Function.class);
        var attributes = new org.springframework.transaction.annotation.AnnotationTransactionAttributeSource()
                .getTransactionAttribute(method, JpaUserActiveRoleRepository.class);
        assertThat(attributes).isNotNull();
        assertThat(attributes.rollbackOn(new top.egon.cola.platform.tianquan.jianshen.core.rule.Rbac3RuleViolation(
                "ROLE_ACTIVATION_SET_INVALID"))).isFalse();
        assertThat(attributes.rollbackOn(new IllegalStateException("write failed"))).isTrue();
    }
}
