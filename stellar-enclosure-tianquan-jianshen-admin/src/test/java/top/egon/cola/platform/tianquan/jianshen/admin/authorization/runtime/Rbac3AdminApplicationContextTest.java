package top.egon.cola.platform.tianquan.jianshen.admin.authorization.runtime;

import jakarta.persistence.EntityManager;
import jakarta.persistence.EntityManagerFactory;
import org.flywaydb.core.Flyway;
import org.flywaydb.core.api.MigrationInfo;
import org.flywaydb.core.api.MigrationInfoService;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.ObjectProvider;
import org.springframework.beans.factory.support.StaticListableBeanFactory;
import org.springframework.boot.autoconfigure.condition.ConditionalOnProperty;
import org.springframework.boot.health.contributor.Status;
import org.springframework.context.annotation.Bean;
import org.springframework.core.env.Environment;
import org.springframework.mock.env.MockEnvironment;
import top.egon.cola.component.outbox.api.TransactionalOutbox;
import top.egon.cola.component.outbox.persistence.OutboxSchemaMetadataValidator;
import top.egon.cola.platform.tianquan.jianshen.admin.authorization.runtime.controller.Rbac3ReadinessIndicator;
import top.egon.cola.platform.tianquan.jianshen.admin.authorization.runtime.domain.vo.ReadinessCheckVO;
import top.egon.cola.platform.tianquan.jianshen.admin.authorization.runtime.repository.tianshu.AtomicRbac3RuntimePolicy;
import top.egon.cola.platform.tianquan.jianshen.admin.authorization.runtime.repository.tianshu.DdcConfigClientStatusRepository;
import top.egon.cola.platform.tianquan.jianshen.admin.authorization.runtime.service.ControlPlaneRuntimeStatusPort;
import top.egon.cola.platform.tianquan.jianshen.admin.config.flyway.Rbac3FlywayConfiguration;
import top.egon.cola.platform.tianquan.jianshen.admin.config.properties.Rbac3AdminProperties;
import top.egon.cola.platform.tianquan.jianshen.admin.config.runtime.Rbac3ApplicationConfiguration;
import top.egon.cola.platform.tianquan.jianshen.admin.config.runtime.Rbac3PlatformIntegrationConfiguration;

import javax.sql.DataSource;
import java.lang.reflect.Method;
import java.util.Arrays;
import java.util.List;
import java.util.function.BooleanSupplier;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.ArgumentMatchers.anyString;
import static org.mockito.Mockito.*;

class Rbac3AdminApplicationContextTest {
    @Test
    void usesIndependentFlywayHistoriesOnTheSameDataSource() {
        DataSource dataSource = mock(DataSource.class);
        Flyway rbac3 = Rbac3FlywayConfiguration.buildRbac3Flyway(dataSource);
        Flyway outbox = Rbac3FlywayConfiguration.buildOutboxFlyway(dataSource);
        assertThat(rbac3.getConfiguration().getDataSource()).isSameAs(dataSource);
        assertThat(outbox.getConfiguration().getDataSource()).isSameAs(dataSource);
        assertThat(rbac3.getConfiguration().getTable()).isEqualTo("flyway_schema_history_rbac3");
        assertThat(outbox.getConfiguration().getTable()).isEqualTo("flyway_schema_history_outbox");
        assertThat(rbac3.getConfiguration().getLocations()).extracting(Object::toString).containsExactly("classpath:db/migration");
        assertThat(outbox.getConfiguration().getLocations()).extracting(Object::toString).containsExactly("classpath:db/transactional-outbox/postgresql");
        assertThat(outbox.getConfiguration().isBaselineOnMigrate()).isTrue();
        assertThat(outbox.getConfiguration().getBaselineVersion().getVersion()).isEqualTo("0");
    }

    @Test
    void readinessFailsClosedWhenAnyApplicationPrerequisiteFails() {
        var indicator = new Rbac3ReadinessIndicator(List.of(new ReadinessCheckVO("rbac3Flyway", () -> true),
                new ReadinessCheckVO("outboxFlyway", () -> false)), () -> "UNKNOWN");
        assertThat(indicator.health().getStatus()).isEqualTo(Status.DOWN);
        assertThat(indicator.health().getDetails()).containsEntry("failedCheck", "outboxFlyway")
                .containsEntry("gatewayRouteability", "UNKNOWN");
    }

    @Test
    void routeabilityIsReportedButDoesNotCreateAStartupDeadlock() {
        var indicator = new Rbac3ReadinessIndicator(List.of(new ReadinessCheckVO("application", () -> true)), () -> "NOT_ROUTABLE");
        assertThat(indicator.health().getStatus()).isEqualTo(Status.UP);
        assertThat(indicator.health().getDetails()).containsEntry("gatewayRouteability", "NOT_ROUTABLE");
        indicator.stopAcceptingTraffic();
        assertThat(indicator.health().getStatus()).isEqualTo(Status.DOWN);
        assertThat(indicator.health().getDetails()).containsEntry("failedCheck", "trafficAcceptance");
    }

    @Test
    void runtimePolicyRetainsItsConfiguredInitialValueWithoutAnyDdcLease() throws Exception {
        var properties = new Rbac3AdminProperties();
        properties.setMaximumActiveRoots(9);
        assertThat(new AtomicRbac3RuntimePolicy(properties).current().maximumActiveRoots()).isEqualTo(9);
        Method factory = Rbac3ApplicationConfiguration.class.getDeclaredMethod("rbac3RuntimePolicy", Rbac3AdminProperties.class);
        assertThat(factory.getAnnotation(Bean.class)).isNotNull();
        assertThat(factory.getAnnotation(ConditionalOnProperty.class)).isNull();
    }

    @Test
    void productionAssemblyNoLongerDeclaresHttpPublicationOrLeaseRuntimeInputs() {
        var methods = Arrays.asList(Rbac3PlatformIntegrationConfiguration.class.getDeclaredMethods());
        assertThat(methods).extracting(Method::getName).doesNotContain("ddcHttpRegistrationServerReadyListener", "gatewayDdcRuntimeStatusService",
                        "ddcProviderLeaseStatusService", "rbac3ServiceIdentity");
        assertThat(methods.stream().flatMap(value -> Arrays.stream(value.getParameterTypes())).map(Class::getName).toList())
                .noneMatch(value -> value.contains("DdcHttpRegistration") || value.endsWith("DdcRuntimeCoordinator"));
    }

    @Test
    void actualProductionReadinessRequiresTheNativeProbeEvenWithReportingDisabled() throws Exception {
        Method factory = readinessFactory();
        assertThat(factory.getAnnotation(ConditionalOnProperty.class)).isNull();
        var nativeConfig = mock(DdcConfigClientStatusRepository.class);
        when(nativeConfig.ready()).thenReturn(true);
        var fixture = new ReadinessFixture();
        var indicator = fixture.create(nativeConfig, "prod", true);
        assertThat(indicator.health().getStatus()).isEqualTo(Status.UP);
        assertThat(indicator.health().getDetails()).containsEntry("gatewayRouteability", "UNKNOWN");
        when(nativeConfig.ready()).thenReturn(false);
        assertThat(indicator.health().getStatus()).isEqualTo(Status.DOWN);
        assertThat(indicator.health().getDetails()).containsEntry("failedCheck", "ddcConfigClient");
        when(nativeConfig.ready()).thenThrow(new IllegalStateException("native authority unavailable"));
        assertThat(indicator.health().getStatus()).isEqualTo(Status.DOWN);
        assertThat(fixture.create(null, "prod", true).health().getStatus()).isEqualTo(Status.DOWN);
        assertThat(fixture.create(null, "", true).health().getStatus()).isEqualTo(Status.DOWN);
    }

    @Test
    void actualReadinessPreservesAuditDatabaseOutboxAndTrafficDrainChecks() throws Exception {
        var nativeConfig = mock(DdcConfigClientStatusRepository.class);
        when(nativeConfig.ready()).thenReturn(true);
        var fixture = new ReadinessFixture();
        assertThat(fixture.create(nativeConfig, "prod", false).health().getDetails()).containsEntry("failedCheck", "oauthAudit");
        doThrow(new IllegalStateException("schema unavailable")).when(fixture.schema).validate();
        assertThat(fixture.create(nativeConfig, "prod", true).health().getDetails()).containsEntry("failedCheck", "outboxManagedSchema");
        doNothing().when(fixture.schema).validate();
        when(fixture.entityManagerFactory.isOpen()).thenReturn(false);
        assertThat(fixture.create(nativeConfig, "prod", true).health().getDetails()).containsEntry("failedCheck", "jpa");
        when(fixture.entityManagerFactory.isOpen()).thenReturn(true);
        var indicator = fixture.create(nativeConfig, "prod", true);
        indicator.stopAcceptingTraffic();
        assertThat(indicator.health().getDetails()).containsEntry("failedCheck", "trafficAcceptance");
    }

    private static Method readinessFactory() throws Exception {
        Method factory = Rbac3PlatformIntegrationConfiguration.class.getDeclaredMethod("rbac3ReadinessIndicator",
                Flyway.class, OutboxSchemaMetadataValidator.class, EntityManagerFactory.class, TransactionalOutbox.class,
                EntityManager.class, ObjectProvider.class, ControlPlaneRuntimeStatusPort.class, Environment.class, ObjectProvider.class);
        factory.setAccessible(true);
        return factory;
    }
    private static <T> ObjectProvider<T> provider(Class<T> type, T instance) {
        var beans = new StaticListableBeanFactory();
        if (instance != null) beans.addBean("fixture", instance);
        return beans.getBeanProvider(type);
    }
    private static final class ReadinessFixture {
        final Flyway flyway = mock(Flyway.class);
        final OutboxSchemaMetadataValidator schema = mock(OutboxSchemaMetadataValidator.class);
        final EntityManagerFactory entityManagerFactory = mock(EntityManagerFactory.class);
        final EntityManager entityManager = mock(EntityManager.class);
        final TransactionalOutbox outbox = mock(TransactionalOutbox.class);
        final ControlPlaneRuntimeStatusPort status = mock(ControlPlaneRuntimeStatusPort.class);
        ReadinessFixture() {
            var migrations = mock(MigrationInfoService.class);
            when(flyway.info()).thenReturn(migrations);
            when(migrations.pending()).thenReturn(new MigrationInfo[0]);
            when(migrations.current()).thenReturn(mock(MigrationInfo.class));
            when(entityManagerFactory.isOpen()).thenReturn(true);
            var query = mock(jakarta.persistence.Query.class);
            when(entityManager.createNativeQuery(anyString())).thenReturn(query);
            when(query.getSingleResult()).thenReturn(0L);
            when(status.status()).thenThrow(new IllegalStateException("no Cilium observation"));
        }
        Rbac3ReadinessIndicator create(DdcConfigClientStatusRepository config, String environment, boolean audit) throws Exception {
            var properties = new MockEnvironment().withProperty("egon.cola.component.rpc.identity.env", environment)
                    .withProperty("egon.cola.component.yuheng.reporting.enabled", "false");
            return (Rbac3ReadinessIndicator) readinessFactory().invoke(new Rbac3PlatformIntegrationConfiguration(),
                    flyway, schema, entityManagerFactory, outbox, entityManager,
                    provider(DdcConfigClientStatusRepository.class, config), status, properties,
                    provider(BooleanSupplier.class, () -> audit));
        }
    }
}
