package top.egon.cola.platform.tianquan.jianshen.admin.authorization.grant.application.service;

import org.junit.jupiter.api.Test;
import jakarta.persistence.EntityManager;
import jakarta.persistence.TypedQuery;
import org.mockito.ArgumentCaptor;
import top.egon.cola.component.common.id.snowflake.SnowflakeIdGenerator;
import top.egon.cola.platform.tianquan.jianshen.admin.authorization.grant.application.domain.enums.TenantApplicationStatusEnum;
import top.egon.cola.platform.tianquan.jianshen.admin.authorization.grant.application.domain.po.TenantApplicationPO;
import top.egon.cola.platform.tianquan.jianshen.admin.iam.application.domain.po.ApplicationPO;
import top.egon.cola.platform.tianquan.jianshen.admin.iam.application.repository.jpa.JpaTenantApplicationRepository;
import top.egon.cola.platform.tianquan.jianshen.admin.iam.business.domain.vo.ApplicationCatalogEntry;

import java.time.Duration;
import java.time.Instant;
import java.util.List;
import java.util.stream.Stream;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;
import static org.mockito.ArgumentMatchers.*;
import static org.mockito.Mockito.*;

class TenantApplicationServiceTest {

    private static final Instant NOW = Instant.parse("2026-08-18T02:00:00Z");

    @Test
    void manualAdmissionKeepsCatalogIdentityInTheSourceIdAndUsesTheExistingSourceContract() {
        SnowflakeIdGenerator.initialize(0L, Duration.ofMillis(5));
        EntityManager entities = mock(EntityManager.class);
        TypedQuery<ApplicationPO> catalogQuery = mock(TypedQuery.class);
        TypedQuery<Long> entitlementQuery = mock(TypedQuery.class);
        ApplicationPO application = new ApplicationPO(9L, 7L, "ddc-app", "ddc-biz",
                "catalog-app", "Catalog", 10, "admin", NOW);
        when(entities.createQuery(anyString(), eq(ApplicationPO.class))).thenReturn(catalogQuery);
        when(catalogQuery.setParameter("ddcApplicationId", "ddc-app")).thenReturn(catalogQuery);
        when(catalogQuery.getResultStream()).thenReturn(Stream.of(application));
        when(entities.createQuery(anyString(), eq(Long.class))).thenReturn(entitlementQuery);
        when(entitlementQuery.setParameter(anyString(), any())).thenReturn(entitlementQuery);
        when(entitlementQuery.setMaxResults(1)).thenReturn(entitlementQuery);
        when(entitlementQuery.getResultList()).thenReturn(List.of());
        var repository = new JpaTenantApplicationRepository(entities, () -> NOW);

        repository.admit(7L, new ApplicationCatalogEntry("ddc-app", "ddc-biz", "biz", "catalog-app",
                "Catalog", true, true), 10, "admin");

        ArgumentCaptor<TenantApplicationPO> persisted = ArgumentCaptor.forClass(TenantApplicationPO.class);
        verify(entities).persist(persisted.capture());
        assertThat(persisted.getValue().getSourceType()).isEqualTo("MANUAL");
        assertThat(persisted.getValue().getSourceId()).isEqualTo("ddc-app");
        assertThat(persisted.getValue().getApplicationId()).isEqualTo(9L);
        assertThat(persisted.getValue().getTenantId()).isEqualTo(7L);
    }

    @Test
    void activeEntitlementIsEffectiveOnlyInsideItsWindow() {
        TenantApplicationPO entitlement = new TenantApplicationPO(
                1L, 7L, 9L, TenantApplicationStatusEnum.ACTIVE,
                NOW, NOW.plusSeconds(300), "MANUAL", "ticket-1",
                "initial purchase", "T-1", "admin", NOW);

        assertThat(entitlement.isEffectiveAt(NOW)).isTrue();
        assertThat(entitlement.isEffectiveAt(NOW.plusSeconds(299))).isTrue();
        assertThat(entitlement.isEffectiveAt(NOW.plusSeconds(300))).isFalse();
    }

    @Test
    void statusChangeUsesOptimisticVersion() {
        TenantApplicationPO entitlement = new TenantApplicationPO(
                1L, 7L, 9L, TenantApplicationStatusEnum.ACTIVE,
                NOW, null, "MANUAL", "ticket-1",
                null, null, "admin", NOW);

        assertThat(entitlement.changeStatus(
                TenantApplicationStatusEnum.SUSPENDED, 0L, "admin", NOW.plusSeconds(1)))
                .isTrue();
        assertThat(entitlement.getStatus())
                .isEqualTo(TenantApplicationStatusEnum.SUSPENDED);
        assertThatThrownBy(() -> entitlement.changeStatus(
                TenantApplicationStatusEnum.ACTIVE, 1L, "admin", NOW.plusSeconds(2)))
                .isInstanceOf(IllegalStateException.class);
    }

    @Test
    void statusChangeLoadsWithoutALockAndFlushesTheVersionedUpdate() throws Exception {
        var entities = mock(EntityManager.class);
        var entitlement = new TenantApplicationPO(1L, 7L, 9L, TenantApplicationStatusEnum.ACTIVE,
                NOW, null, "MANUAL", "ticket-1", null, null, "admin", NOW);
        var application = new ApplicationPO(9L, 7L, "ddc-app", "ddc-biz", "catalog-app", "Catalog", 10, "admin", NOW);
        when(entities.find(TenantApplicationPO.class, 1L)).thenReturn(entitlement);
        when(entities.find(ApplicationPO.class, 9L)).thenReturn(application);
        var repository = new JpaTenantApplicationRepository(entities, () -> NOW.plusSeconds(1));

        assertThat(repository.changeStatus(7L, 1L, "SUSPENDED", 0L, "admin").status()).isEqualTo("SUSPENDED");

        verify(entities).find(TenantApplicationPO.class, 1L);
        verify(entities, never()).find(eq(TenantApplicationPO.class), any(), any(jakarta.persistence.LockModeType.class));
        verify(entities).flush();
        assertThat(top.egon.cola.platform.tianquan.jianshen.admin.shared.domain.po.TenantScopedPO.class
                .getDeclaredField("version").isAnnotationPresent(jakarta.persistence.Version.class)).isTrue();
    }

    @Test
    void unchangedReplicaStatusMustStillMatchThePrimaryVersion() {
        var entities = mock(EntityManager.class);
        var entitlement = new TenantApplicationPO(1L, 7L, 9L, TenantApplicationStatusEnum.ACTIVE,
                NOW, null, "MANUAL", "ticket-1", null, null, "admin", NOW);
        var application = new ApplicationPO(9L, 7L, "ddc-app", "ddc-biz", "catalog-app", "Catalog", 10, "admin", NOW);
        var update = mock(jakarta.persistence.Query.class, RETURNS_SELF);
        when(entities.find(TenantApplicationPO.class, 1L)).thenReturn(entitlement);
        when(entities.find(ApplicationPO.class, 9L)).thenReturn(application);
        when(entities.createNativeQuery(anyString())).thenReturn(update);
        when(update.executeUpdate()).thenReturn(1, 0);
        var repository = new JpaTenantApplicationRepository(entities, () -> NOW.plusSeconds(1));

        assertThat(repository.changeStatus(7L, 1L, "ACTIVE", 0L, "admin").status()).isEqualTo("ACTIVE");
        assertThatThrownBy(() -> repository.changeStatus(7L, 1L, "ACTIVE", 0L, "admin"))
                .isInstanceOf(IllegalStateException.class).hasMessage("tenant application version conflict");
        verify(entities, times(2)).createNativeQuery(argThat(sql -> sql.toLowerCase(java.util.Locale.ROOT)
                .contains("update rbac3_tenant_application set version = version")
                && sql.contains("tenant_id = :tenant") && sql.contains("version = :version")
                && sql.contains("status = :status")));
    }

    @Test
    void optimisticConflictAtFlushFailsTheTransactionBeforeReturningAResult() {
        var entities = mock(EntityManager.class);
        var entitlement = new TenantApplicationPO(1L, 7L, 9L, TenantApplicationStatusEnum.ACTIVE,
                NOW, null, "MANUAL", "ticket-1", null, null, "admin", NOW);
        when(entities.find(TenantApplicationPO.class, 1L)).thenReturn(entitlement);
        doThrow(new jakarta.persistence.OptimisticLockException("concurrent update")).when(entities).flush();
        var repository = new JpaTenantApplicationRepository(entities, () -> NOW.plusSeconds(1));

        assertThatThrownBy(() -> repository.changeStatus(7L, 1L, "SUSPENDED", 0L, "admin"))
                .isInstanceOf(jakarta.persistence.OptimisticLockException.class);
        verify(entities, never()).find(ApplicationPO.class, 9L);
    }
}
