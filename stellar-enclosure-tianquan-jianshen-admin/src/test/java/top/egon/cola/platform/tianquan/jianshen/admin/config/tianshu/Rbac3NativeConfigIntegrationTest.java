package top.egon.cola.platform.tianquan.jianshen.admin.config.tianshu;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.node.IntNode;
import com.fasterxml.jackson.databind.node.NullNode;
import io.micrometer.core.instrument.MeterRegistry;
import io.micrometer.core.instrument.simple.SimpleMeterRegistry;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.support.StaticListableBeanFactory;
import org.springframework.boot.context.properties.ConfigurationPropertiesBindingPostProcessor;
import org.springframework.boot.context.properties.EnableConfigurationProperties;
import org.springframework.boot.test.context.runner.ApplicationContextRunner;
import org.springframework.context.annotation.AnnotationConfigApplicationContext;
import org.springframework.context.annotation.Configuration;
import org.springframework.core.env.MapPropertySource;
import top.egon.cola.component.tianshu.api.refresh.DdcConfigApplier;
import top.egon.cola.component.tianshu.model.config.DdcConfigurationChangedEvent;
import top.egon.cola.component.tianshu.format.DdcConfigCanonicalJson;
import top.egon.cola.component.tianshu.format.DdcConfigFormatStrategyRegistry;
import top.egon.cola.component.tianshu.model.config.DdcConfigBaselineVO;
import top.egon.cola.component.tianshu.model.config.DdcConfigScopeVO;
import top.egon.cola.component.tianshu.model.config.DdcConfigSnapshotDTO;
import top.egon.cola.component.tianshu.environment.DdcDynamicPropertySource;
import top.egon.cola.component.tianshu.service.config.DdcConfigSnapshotCoordinator;
import top.egon.cola.component.tianshu.service.refresh.DdcConfigurationPropertiesRebinder;
import top.egon.cola.component.tianshu.service.binding.DdcFieldBindingService;
import top.egon.cola.component.tianshu.service.binding.DdcValueBindingRegistry;
import top.egon.cola.component.tianshu.service.refresh.DdcYamlConfigApplier;
import top.egon.cola.component.tianshu.service.refresh.DefaultDdcConfigApplierRegistry;
import top.egon.cola.component.tianshu.state.DdcLocalConfigState;
import top.egon.cola.component.tianshu.state.DdcLocalConfigState.DeliveryObservationVO;
import top.egon.cola.component.tianshu.state.DdcLocalConfigState.DeliveryStatusEnum;
import top.egon.cola.platform.tianquan.jianshen.admin.authorization.runtime.repository.tianshu.AtomicRbac3RuntimePolicy;
import top.egon.cola.platform.tianquan.jianshen.admin.authorization.runtime.repository.tianshu.DdcConfigClientStatusRepository;
import top.egon.cola.platform.tianquan.jianshen.admin.authorization.runtime.repository.tianshu.Rbac3DdcPolicyApplier;
import top.egon.cola.platform.tianquan.jianshen.admin.config.properties.Rbac3AdminProperties;

import java.time.Clock;
import java.time.Instant;
import java.time.ZoneOffset;
import java.util.ArrayList;
import java.util.List;
import java.util.Map;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.when;

class Rbac3NativeConfigIntegrationTest {

    private static final String KEY = AtomicRbac3RuntimePolicy.MAXIMUM_ACTIVE_ROOTS_KEY;
    private static final Instant NOW = Instant.parse("2026-11-18T12:00:00Z");
    private static final String DIGEST = "sha256:" + "a".repeat(64);
    private static final DdcConfigScopeVO SCOPE = new DdcConfigScopeVO(
            "1001", "permission", "prod", "tianquan-jianshen", "application.yml");

    @Test
    void nativeTypedLeafRestoresTheActualRuntimeSnapshotAndVersion() {
        var policy = new AtomicRbac3RuntimePolicy(new Rbac3AdminProperties());
        String key = AtomicRbac3RuntimePolicy.MAXIMUM_ACTIVE_ROOTS_KEY;
        policy.apply(key, "7", 41L);
        var original = policy.current();
        DdcConfigApplier candidate = new Rbac3DdcPolicyApplier(key, 0, policy);
        assertThat(candidate).isInstanceOf(DdcYamlConfigApplier.TypedLeafApplier.class);
        var typed = (DdcYamlConfigApplier.TypedLeafApplier) candidate;
        var rule = new DdcConfigBaselineVO.RuleVO(key, DdcConfigBaselineVO.ReloadModeEnum.HOT,
                "INTEGER", null, false, true);
        var prepared = typed.prepare(key, new DdcYamlConfigApplier.ValueVO(true, IntNode.valueOf(12), "12"),
                new DdcYamlConfigApplier.ValueVO(true, IntNode.valueOf(16), "16"), rule, 50L);

        assertThat(policy.current()).isSameAs(original);
        prepared.commit();
        assertThat(policy.current().maximumActiveRoots()).isEqualTo(12);
        prepared.rollback();
        assertThat(policy.current()).isSameAs(original);
        assertThat(policy.current().configVersions()).containsEntry(key, 41L);
    }

    @Test
    void nativePreparationIsPureAndRollbackRestoresPreviousDiagnostics() {
        var policy = new AtomicRbac3RuntimePolicy(new Rbac3AdminProperties());
        policy.apply(KEY, "7", 41L);
        assertThatThrownBy(() -> policy.apply(KEY, "33", 42L)).isInstanceOf(IllegalArgumentException.class);
        var old = policy.current();
        var diagnostic = policy.lastApplyFailure();
        var typed = new Rbac3DdcPolicyApplier(KEY, 0, policy);

        assertThatThrownBy(() -> typed.prepare(KEY, value(33), value(16), rule(), 50L))
                .isInstanceOf(RuntimeException.class);
        assertThatThrownBy(() -> typed.prepare(KEY,
                new DdcYamlConfigApplier.ValueVO(true, NullNode.instance, null), value(16), rule(), 50L))
                .isInstanceOf(IllegalArgumentException.class);
        assertThat(policy.current()).isSameAs(old);
        assertThat(policy.lastApplyFailure()).isEqualTo(diagnostic);

        var prepared = typed.prepare(KEY, value(12), value(16), rule(), 50L);
        assertThat(policy.current()).isSameAs(old);
        assertThat(policy.lastApplyFailure()).isEqualTo(diagnostic);
        prepared.commit();
        assertThat(policy.lastApplyFailure()).isEmpty();
        prepared.rollback();
        assertThat(policy.current()).isSameAs(old);
        assertThat(policy.lastApplyFailure()).isEqualTo(diagnostic);
    }

    @Test
    void deletedKeyUsesValidatedLocalFallbackAndCannotRemoveTheRootLimit() {
        var policy = new AtomicRbac3RuntimePolicy(new Rbac3AdminProperties());
        policy.apply(KEY, "7", 41L);
        var original = policy.current();
        var typed = new Rbac3DdcPolicyApplier(KEY, 0, policy);
        var fallback = typed.prepare(KEY, new DdcYamlConfigApplier.ValueVO(false, null, "16"), value(16), rule(), 50L);
        fallback.commit();
        assertThat(policy.current().maximumActiveRoots()).isEqualTo(16);
        fallback.rollback();
        assertThat(policy.current()).isSameAs(original);
        assertThatThrownBy(() -> typed.prepare(KEY, new DdcYamlConfigApplier.ValueVO(false, null, null),
                value(16), rule(), 51L)).isInstanceOf(RuntimeException.class);
        assertThat(policy.current()).isSameAs(original);
    }

    @Test
    void laterNativePersistenceFailureRestoresActualPolicyAndPropertySource() {
        try (var context = new AnnotationConfigApplicationContext()) {
            Map<String, JsonNode> oldValues = Map.of(KEY, IntNode.valueOf(16));
            var source = new DdcDynamicPropertySource("tianshu:application.yml",
                    DdcDynamicPropertySource.Snapshot.fromTyped("application.yml", 1L, DIGEST, oldValues));
            context.getEnvironment().getPropertySources().addFirst(source);
            context.getEnvironment().getPropertySources().addLast(new MapPropertySource("local", Map.of(KEY, 16)));
            context.register(PropertiesConfiguration.class);
            context.refresh();
            var rebinder = new DdcConfigurationPropertiesRebinder(context,
                    context.getBean(ConfigurationPropertiesBindingPostProcessor.class), context.getEnvironment());
            rebinder.afterSingletonsInstantiated();
            var fields = new DdcFieldBindingService(new DdcValueBindingRegistry(), context.getBeanFactory());
            var registry = new DefaultDdcConfigApplierRegistry((key, value, version) -> { });
            var policy = new AtomicRbac3RuntimePolicy(new Rbac3AdminProperties());
            policy.apply(KEY, "7", 41L);
            var original = policy.current();
            registry.registerExact(KEY, new Rbac3DdcPolicyApplier(KEY, 0, policy));
            var events = new ArrayList<DdcConfigurationChangedEvent>();
            var applier = new DdcYamlConfigApplier(context.getEnvironment(), registry, fields, rebinder,
                    event -> events.add((DdcConfigurationChangedEvent) event), 1024 * 1024,
                    DdcConfigFormatStrategyRegistry.defaults(), Clock.fixed(NOW, ZoneOffset.UTC));

            assertThatThrownBy(() -> applier.applySnapshot(SCOPE, DIGEST, List.of(rule()), snapshot(2, 12),
                    null, ignored -> { throw new IllegalStateException("fixture-durable-write-failed"); }))
                    .hasMessage("fixture-durable-write-failed");
            assertThat(policy.current()).isSameAs(original);
            assertThat(source.snapshot().version()).isEqualTo(1L);
            assertThat(events).isEmpty();

            applier.applySnapshot(SCOPE, DIGEST, List.of(rule()), snapshot(2, 12), null);
            assertThat(policy.current().maximumActiveRoots()).isEqualTo(12);
            assertThat(policy.current().configVersions()).containsEntry(KEY, 2L);
            assertThat(source.snapshot().version()).isEqualTo(2L);
            assertThat(events).hasSize(1);
        }
    }

    @Test
    void nativeReadinessAndMetricsNeedCurrentAuthorityButNeverALease() {
        var local = new DdcLocalConfigState(1001L);
        var runtime = mock(DdcConfigSnapshotCoordinator.class);
        var metrics = new SimpleMeterRegistry();
        when(runtime.ready()).thenReturn(true);
        local.updateDeliveryObservation(new DeliveryObservationVO(DeliveryStatusEnum.READY,
                "50", "50", NOW, NOW.plusSeconds(60), true, null));
        new ApplicationContextRunner().withUserConfiguration(Rbac3DdcPolicyConfiguration.class)
                .withPropertyValues("egon.cola.component.tianshu.enabled=true")
                .withBean("rbac3RuntimePolicy", AtomicRbac3RuntimePolicy.class,
                        () -> new AtomicRbac3RuntimePolicy(new Rbac3AdminProperties()))
                .withBean("ddcConfigApplierRegistry", DefaultDdcConfigApplierRegistry.class,
                        () -> new DefaultDdcConfigApplierRegistry((key, value, version) -> { }))
                .withBean("ddcLocalConfigState", DdcLocalConfigState.class, () -> local)
                .withBean("ddcConfigSnapshotCoordinator", DdcConfigSnapshotCoordinator.class, () -> runtime)
                .withBean("meterRegistry", MeterRegistry.class, () -> metrics)
                .run(context -> {
                    assertThat(context).hasNotFailed();
                    var status = context.getBean(DdcConfigClientStatusRepository.class);
                    assertThat(status.ready()).isTrue();
                    assertThat(status.status().state()).isEqualTo("READY");
                    assertThat(status.status().instanceId()).isNull();
                    assertThat(status.status().leaseIdFingerprint()).isNull();
                    assertThat(status.status().leaseExpireAt()).isNull();
                    assertThat(metrics.get("tianquan_jianshen_tianshu_config_ready").gauge().value()).isEqualTo(1.0);

                    when(runtime.ready()).thenReturn(false);
                    assertThat(status.ready()).isFalse();
                    assertThat(status.status().state()).isEqualTo("STALE");
                    assertThat(metrics.get("tianquan_jianshen_tianshu_config_ready").gauge().value()).isZero();
                    when(runtime.ready()).thenReturn(true);
                    local.updateDeliveryObservation(new DeliveryObservationVO(DeliveryStatusEnum.ISOLATED,
                            "50", "51", NOW, NOW.plusSeconds(60), false, "AUTHORIZATION_REVOKED"));
                    assertThat(status.ready()).isFalse();
                    assertThat(status.status().state()).isEqualTo("ISOLATED");
                });
    }

    @Test
    void absentNativeStateAndCoordinatorCannotCreateReadyStatus() {
        var beans = new StaticListableBeanFactory();
        var status = new DdcConfigClientStatusRepository(beans.getBeanProvider(DdcLocalConfigState.class),
                beans.getBeanProvider(DdcConfigSnapshotCoordinator.class), new AtomicRbac3RuntimePolicy(new Rbac3AdminProperties()));
        assertThat(status.status().state()).isEqualTo("UNKNOWN");
        assertThat(status.ready()).isFalse();
    }

    @Test
    void preparedRollbackCannotEraseANewerConcurrentDiagnostic() {
        var policy = new AtomicRbac3RuntimePolicy(new Rbac3AdminProperties());
        policy.apply(KEY, "7", 41L);
        var prepared = new Rbac3DdcPolicyApplier(KEY, 0, policy).prepare(KEY, value(12), value(16), rule(), 50L);
        prepared.commit();
        var committed = policy.current();
        assertThatThrownBy(() -> policy.apply(KEY, "33", 51L)).isInstanceOf(IllegalArgumentException.class);
        var newerDiagnostic = policy.lastApplyFailure();

        assertThatThrownBy(prepared::rollback).isInstanceOf(IllegalStateException.class)
                .hasMessage("POLICY_ROLLBACK_STATE_CHANGED");
        assertThat(policy.current()).isSameAs(committed);
        assertThat(policy.lastApplyFailure()).isEqualTo(newerDiagnostic);
    }

    private static DdcYamlConfigApplier.ValueVO value(int value) {
        return new DdcYamlConfigApplier.ValueVO(true, IntNode.valueOf(value), Integer.toString(value));
    }

    private static DdcConfigBaselineVO.RuleVO rule() {
        return new DdcConfigBaselineVO.RuleVO(KEY, DdcConfigBaselineVO.ReloadModeEnum.HOT, "INTEGER", null, false, true);
    }

    private static DdcConfigSnapshotDTO snapshot(long revision, int value) {
        var initial = new DdcConfigSnapshotDTO("1", SCOPE, Long.toString(revision), true, DIGEST, DIGEST,
                Map.of(KEY, IntNode.valueOf(value)), null, NOW.plusSeconds(300));
        return new DdcConfigSnapshotDTO("1", SCOPE, Long.toString(revision), true, DIGEST,
                DdcConfigCanonicalJson.contentSha256(initial), initial.getHotValues(), null, initial.getValidUntil());
    }

    @Configuration(proxyBeanMethods = false)
    @EnableConfigurationProperties
    static class PropertiesConfiguration { }
}
