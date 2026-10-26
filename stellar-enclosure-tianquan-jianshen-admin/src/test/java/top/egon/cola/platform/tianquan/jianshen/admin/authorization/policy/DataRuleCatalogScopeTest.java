package top.egon.cola.platform.tianquan.jianshen.admin.authorization.policy;

import jakarta.persistence.EntityManager;
import jakarta.persistence.LockModeType;
import jakarta.persistence.Query;
import jakarta.persistence.TypedQuery;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.mockito.ArgumentCaptor;
import top.egon.cola.component.common.id.snowflake.SnowflakeIdGenerator;
import top.egon.cola.platform.tianquan.jianshen.admin.authorization.policy.domain.dto.DataRuleCommandDTO;
import top.egon.cola.platform.tianquan.jianshen.admin.authorization.policy.domain.enums.DataRuleScopeTypeEnum;
import top.egon.cola.platform.tianquan.jianshen.admin.authorization.policy.domain.po.DataRulePO;
import top.egon.cola.platform.tianquan.jianshen.admin.authorization.policy.domain.po.DataRuleReferencePO;
import top.egon.cola.platform.tianquan.jianshen.admin.authorization.policy.domain.vo.RuleReferenceVO;
import top.egon.cola.platform.tianquan.jianshen.admin.authorization.policy.repository.jpa.JpaConstraintRepository;
import top.egon.cola.platform.tianquan.jianshen.admin.authorization.runtime.repository.AuthorizationEventPublisher;
import top.egon.cola.platform.tianquan.jianshen.admin.authorization.runtime.state.repository.TenantAuthorizationStateRepository;
import top.egon.cola.platform.tianquan.jianshen.admin.registration.catalog.repository.PermissionCatalogScopeRepository;
import top.egon.cola.platform.tianquan.jianshen.admin.registration.catalog.repository.CatalogAdministrationGuard;
import top.egon.cola.platform.tianquan.jianshen.contract.permission.CatalogScope;
import top.egon.cola.platform.tianquan.jianshen.core.rule.Rbac3RuleViolation;
import top.egon.cola.platform.tianquan.jianshen.starter.security.Rbac3UserDetails;

import java.time.Duration;
import java.time.Instant;
import java.util.List;

import static org.junit.jupiter.api.Assertions.*;
import static org.mockito.ArgumentMatchers.*;
import static org.mockito.Mockito.*;

class DataRuleCatalogScopeTest {
    private static final Instant NOW = Instant.parse("2026-10-25T00:00:00Z");
    private static final CatalogScope TARGET = new CatalogScope("1", "10", "biz", "app", "space", "test");
    private final EntityManager entityManager = mock(EntityManager.class);
    private final CatalogAdministrationGuard guard = mock(CatalogAdministrationGuard.class);
    private final TenantAuthorizationStateRepository policy = mock(TenantAuthorizationStateRepository.class);
    private final AuthorizationEventPublisher events = mock(AuthorizationEventPublisher.class);
    private final Rbac3UserDetails actor = mock(Rbac3UserDetails.class);
    private final Query facts = mock(Query.class, RETURNS_SELF);
    private final Query deleteReferences = mock(Query.class, RETURNS_SELF);
    private final JpaConstraintRepository repository = new JpaConstraintRepository(entityManager, () -> NOW, events, policy, guard);

    @BeforeAll
    static void ids() { SnowflakeIdGenerator.initialize(0L, Duration.ofMillis(5)); }

    @BeforeEach
    void prepare() {
        when(actor.tenantId()).thenReturn("10");
        when(actor.rbac3UserId()).thenReturn("90");
        when(guard.require(eq(TARGET), same(actor), anyString(), eq(NOW)))
                .thenReturn(new PermissionCatalogScopeRepository.ScopeState(TARGET, 20, 3, 0));
        when(entityManager.createNativeQuery(anyString())).thenReturn(facts);
        when(facts.getResultList()).thenReturn(List.<Object[]>of(new Object[] {30L, 40L}));
        when(entityManager.createQuery(contains("delete from DataRuleReferenceEntity"))).thenReturn(deleteReferences);
        when(policy.increment(10L, "90")).thenReturn(4L);
        when(events.enqueue(any())).thenReturn("propagation");
    }

    @Test
    void createUsesCatalogForeignKeysAndPublishesTheExistingPolicyMutation() {
        var result = repository.saveDataRule(command(null, 0));
        var inserted = ArgumentCaptor.forClass(Object.class);
        verify(entityManager, times(2)).persist(inserted.capture());
        DataRulePO rule = (DataRulePO) inserted.getAllValues().getFirst();
        assertEquals(1L, rule.getCatalogScopeId());
        assertEquals(10L, rule.getTenantId());
        assertEquals(20L, rule.getApplicationId());
        assertEquals(30L, rule.getRoleId());
        assertEquals(40L, rule.getPermissionId());
        assertInstanceOf(DataRuleReferencePO.class, inserted.getAllValues().get(1));
        assertEquals(rule.getId().toString(), result.resourceId());
        verify(facts).setParameter("scope", 1L);
        verify(facts).setParameter("tenant", 10L);
        verify(facts).setParameter("application", 20L);
        verify(entityManager).createNativeQuery(argThat(sql -> sql.contains("rbac3_catalog_role_binding")
                && sql.contains("rbac3_catalog_permission") && sql.contains("b.enabled") && sql.contains("for share of b, r, p")));
        var order = inOrder(guard, entityManager, policy, events);
        order.verify(guard).require(TARGET, actor, "system:data-rule:manage", NOW);
        order.verify(entityManager).createNativeQuery(anyString());
        order.verify(entityManager).persist(any(DataRulePO.class));
        order.verify(entityManager).persist(any(DataRuleReferencePO.class));
        order.verify(policy).increment(10L, "90");
        order.verify(events).enqueue(argThat(event -> event.eventType().equals("DATA_RULE_CHANGED")));
    }

    @Test
    @SuppressWarnings("unchecked")
    void readsRequireFullTargetAndReturnOnlyThatScope() {
        TypedQuery<DataRulePO> rules = mock(TypedQuery.class, RETURNS_SELF);
        TypedQuery<DataRuleReferencePO> references = mock(TypedQuery.class, RETURNS_SELF);
        when(entityManager.createQuery(contains("select r from DataRuleEntity"), eq(DataRulePO.class))).thenReturn(rules);
        when(entityManager.createQuery(contains("select r from DataRuleReferenceEntity"), eq(DataRuleReferencePO.class))).thenReturn(references);
        when(rules.getResultList()).thenReturn(List.of(existing(1, 30, 40)));
        when(references.getResultList()).thenReturn(List.of());
        var rows = repository.dataRules(TARGET, actor);
        assertEquals(TARGET, rows.getFirst().target());
        assertEquals("40", rows.getFirst().permissionId());
        verify(rules).setParameter("scopeId", 1L);
        verify(rules).setParameter("tenantId", 10L);
        verify(rules).setParameter("applicationId", 20L);
        verify(guard).require(TARGET, actor, "system:data-rule:read", NOW);
        assertEquals("REQUEST_INVALID", assertThrows(Rbac3RuleViolation.class, () -> repository.dataRules(null, actor)).reasonCode());
    }

    @Test
    void missingScopeCrossTenantAndMalformedIdsHaveNoPersistencePath() {
        assertThrows(Rbac3RuleViolation.class, () -> new DataRuleCommandDTO(null, "10", null, "20", "30", "40", "SELF", null,
                List.of(), NOW, null, 0, actor));
        assertThrows(Rbac3RuleViolation.class, () -> new DataRuleCommandDTO(TARGET, "11", null, "20", "30", "40", "SELF", null,
                List.of(), NOW, null, 0, actor));
        assertThrows(Rbac3RuleViolation.class, () -> new DataRuleCommandDTO(TARGET, "10", null, "020", "30", "40", "SELF", null,
                List.of(), NOW, null, 0, actor));
        verifyNoInteractions(entityManager, guard, policy, events);
    }

    @Test
    void disabledOrForeignCatalogFactsCannotInsertOrChangePolicy() {
        when(facts.getResultList()).thenReturn(List.of());
        assertEquals("APPLICATION_BINDING_DENIED", assertThrows(Rbac3RuleViolation.class,
                () -> repository.saveDataRule(command(null, 0))).reasonCode());
        verify(entityManager, never()).persist(any());
        verifyNoInteractions(policy, events);
    }

    @Test
    void claimedApplicationMustMatchTheLockedScope() {
        when(guard.require(TARGET, actor, "system:data-rule:manage", NOW))
                .thenReturn(new PermissionCatalogScopeRepository.ScopeState(TARGET, 21, 3, 0));
        assertEquals("APPLICATION_BINDING_DENIED", assertThrows(Rbac3RuleViolation.class,
                () -> repository.saveDataRule(command(null, 0))).reasonCode());
        verifyNoInteractions(entityManager, policy, events);
    }

    @Test
    void anUpdateCannotMoveScopeRoleOrPermissionOrDeleteTheirReferences() {
        for (DataRulePO existing : List.of(existing(2, 30, 40), existing(1, 31, 40), existing(1, 30, 41))) {
            when(entityManager.find(DataRulePO.class, 100L, LockModeType.PESSIMISTIC_WRITE)).thenReturn(existing);
            assertEquals("APPLICATION_BINDING_DENIED", assertThrows(Rbac3RuleViolation.class,
                    () -> repository.saveDataRule(command("100", 0))).reasonCode());
            assertEquals(DataRuleScopeTypeEnum.SELF, existing.getScopeType());
        }
        verify(entityManager, never()).createQuery(contains("delete from DataRuleReferenceEntity"));
        verify(entityManager, never()).persist(any());
        verifyNoInteractions(policy, events);
    }

    @Test
    void staleVersionAndStaleUserSnapshotStopBeforeReferenceReplacement() {
        when(entityManager.find(DataRulePO.class, 100L, LockModeType.PESSIMISTIC_WRITE)).thenReturn(existing(1, 30, 40));
        assertEquals("RESOURCE_VERSION_CONFLICT", assertThrows(Rbac3RuleViolation.class,
                () -> repository.saveDataRule(command("100", 1))).reasonCode());
        when(guard.require(TARGET, actor, "system:data-rule:manage", NOW)).thenThrow(new Rbac3RuleViolation("AUTH_SNAPSHOT_NOT_READY"));
        assertEquals("AUTH_SNAPSHOT_NOT_READY", assertThrows(Rbac3RuleViolation.class,
                () -> repository.saveDataRule(command("100", 0))).reasonCode());
        verify(entityManager, never()).createQuery(contains("delete from DataRuleReferenceEntity"));
        verifyNoInteractions(policy, events);
    }

    @Test
    void aValidUpdatePreservesIdentityAndReplacesReferencesInsideTheCommand() {
        DataRulePO existing = existing(1, 30, 40);
        when(entityManager.find(DataRulePO.class, 100L, LockModeType.PESSIMISTIC_WRITE)).thenReturn(existing);
        repository.saveDataRule(command("100", 0));
        assertEquals(DataRuleScopeTypeEnum.DEPT_TREE, existing.getScopeType());
        assertEquals(1L, existing.getCatalogScopeId());
        verify(deleteReferences).setParameter("tenantId", 10L);
        verify(deleteReferences).setParameter("ruleId", 100L);
        verify(deleteReferences).executeUpdate();
        verify(entityManager).persist(any(DataRuleReferencePO.class));
        verify(policy).increment(10L, "90");
    }

    private DataRulePO existing(long scope, long role, long permission) {
        return new DataRulePO(100L, 10L, scope, 20L, role, permission, DataRuleScopeTypeEnum.SELF, null, NOW, null, "90", NOW);
    }

    private DataRuleCommandDTO command(String id, long expected) {
        return new DataRuleCommandDTO(TARGET, "10", id, "20", "30", "40", "DEPT_TREE", 5L,
                List.of(new RuleReferenceVO("DEPT", "50")), NOW, null, expected, actor);
    }
}
