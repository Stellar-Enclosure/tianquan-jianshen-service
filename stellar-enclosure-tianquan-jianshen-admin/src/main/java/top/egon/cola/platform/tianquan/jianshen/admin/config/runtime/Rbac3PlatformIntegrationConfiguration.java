package top.egon.cola.platform.tianquan.jianshen.admin.config.runtime;

import jakarta.persistence.EntityManager;
import jakarta.persistence.EntityManagerFactory;
import org.flywaydb.core.Flyway;
import org.springframework.beans.factory.annotation.Qualifier;
import org.springframework.boot.autoconfigure.condition.ConditionalOnBean;
import org.springframework.boot.autoconfigure.condition.ConditionalOnMissingBean;
import org.springframework.boot.autoconfigure.condition.ConditionalOnProperty;
import org.springframework.beans.factory.ObjectProvider;
import org.springframework.context.ApplicationListener;
import org.springframework.context.event.ContextClosedEvent;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.context.annotation.Primary;
import org.springframework.orm.jpa.SharedEntityManagerCreator;
import top.egon.cola.component.yuheng.starter.GatewayReportingProperties;
import top.egon.cola.component.yuheng.starter.reporting.GatewayReportingState;
import top.egon.cola.component.outbox.api.TransactionalOutbox;
import top.egon.cola.platform.tianquan.jianshen.admin.authorization.runtime.repository.AuthorizationEventPublisher;
import top.egon.cola.platform.tianquan.jianshen.admin.authorization.runtime.repository.tianshu.DdcConfigClientStatusRepository;
import top.egon.cola.platform.tianquan.jianshen.admin.config.flyway.Rbac3FlywayConfiguration;
import top.egon.cola.platform.tianquan.jianshen.admin.authorization.runtime.repository.http.GatewayDefinitionStatusRepository;
import top.egon.cola.platform.tianquan.jianshen.admin.authorization.runtime.repository.outbox.TransactionalOutboxAuthorizationEventPublisher;
import top.egon.cola.platform.tianquan.jianshen.admin.authorization.runtime.service.Rbac3OperationalRuntimeStatusService;
import top.egon.cola.platform.tianquan.jianshen.admin.authorization.runtime.controller.Rbac3ReadinessIndicator;
import top.egon.cola.platform.tianquan.jianshen.admin.authorization.runtime.service.ControlPlaneRuntimeStatusPort;

import java.time.Clock;
import java.util.List;
import top.egon.cola.platform.tianquan.jianshen.admin.authorization.runtime.domain.vo.ReadinessCheckVO;
import top.egon.cola.platform.tianquan.jianshen.admin.authorization.runtime.domain.vo.RuntimeStatusVO;
import top.egon.cola.platform.tianquan.jianshen.admin.authorization.runtime.domain.vo.DdcConfigClientStatusVO;
import top.egon.cola.platform.tianquan.jianshen.admin.authorization.runtime.domain.vo.DefinitionStatusVO;
import top.egon.cola.platform.tianquan.jianshen.admin.authorization.runtime.domain.vo.ProviderLeaseStatusVO;
import top.egon.cola.platform.tianquan.jianshen.admin.authorization.runtime.domain.vo.GatewayReleaseStatusVO;

/**
 * 类型 `Rbac3PlatformIntegrationConfiguration` 位于当前包内，是类型，用于承载 `Rbac3 Platform Integration Configuration` 相关的职责、状态或契约；调用方通常通过其公开 API、Spring 装配或实现关系使用。
 * Type `Rbac3PlatformIntegrationConfiguration` is a type in its package and carries the responsibility, state, or contract for `Rbac3 Platform Integration Configuration`; callers normally use it through its public API, Spring assembly, or implementation relationship.
 * Wires component-owned Gateway, Tianshu and Outbox runtimes into Tianquan-Jianshen ports.
 */
@Configuration(proxyBeanMethods = false)
public class Rbac3PlatformIntegrationConfiguration {

    /** Exposes the transaction-bound EntityManager used by the existing handwritten JPA repositories. */
    @Bean("jpaSharedEM_entityManagerFactory")
    @ConditionalOnMissingBean(name = "jpaSharedEM_entityManagerFactory")
    EntityManager sharedEntityManager(@Qualifier("entityManagerFactory") EntityManagerFactory factory) {
        return SharedEntityManagerCreator.createSharedEntityManager(factory);
    }

    /** Shares the configured identity clock with the named persistence and Outbox clock. */
    @Bean("egonColaMybatisPlusClock")
    @Primary
    Clock egonColaMybatisPlusClock(@Qualifier("idpClock") Clock clock) {
        return clock;
    }

    /**
     * 方法 `rbac3Clock` 按照 `Rbac3PlatformIntegrationConfiguration` 的职责处理输入，完成 `rbac3 Clock` 操作并返回结果或产生声明的副作用；调用方应遵守参数和异常契约。
     * Method `rbac3Clock` processes its inputs according to `Rbac3PlatformIntegrationConfiguration`'s responsibility, performs the `rbac3 Clock` operation, and returns a result or declared side effect; callers must follow its parameter and exception contract.
     *
     * 用法：调用 `rbac3Clock` 前准备符合契约的参数，并根据返回值、异常或副作用继续业务流程。
     * Usage: provide contract-compliant arguments before calling `rbac3Clock`, then continue the business flow using its result, exception, or side effect.
     *
     * @return 操作产生的结果，其具体语义由返回类型和所属 API 定义；the result of the operation, whose exact semantics are defined by the return type and owning API.
     */
    @Bean
    @ConditionalOnMissingBean
    Clock rbac3Clock() {
        return Clock.systemUTC();
    }

    /**
     * 方法 `authorizationEventPort` 按照 `Rbac3PlatformIntegrationConfiguration` 的职责处理输入，完成 `authorization Event Port` 操作并返回结果或产生声明的副作用；调用方应遵守参数和异常契约。
     * Method `authorizationEventPort` processes its inputs according to `Rbac3PlatformIntegrationConfiguration`'s responsibility, performs the `authorization Event Port` operation, and returns a result or declared side effect; callers must follow its parameter and exception contract.
     *
     * 用法：调用 `authorizationEventPort` 前准备符合契约的参数，并根据返回值、异常或副作用继续业务流程。
     * Usage: provide contract-compliant arguments before calling `authorizationEventPort`, then continue the business flow using its result, exception, or side effect.
     *
     * @param outbox 输入参数 `outbox`，用于确定本次操作的范围或内容；input value used to determine the operation's scope or content.
     * @param clock 输入参数 `clock`，用于确定本次操作的范围或内容；input value used to determine the operation's scope or content.
     * @return 操作产生的结果，其具体语义由返回类型和所属 API 定义；the result of the operation, whose exact semantics are defined by the return type and owning API.
     */
    @Bean
    @ConditionalOnMissingBean(AuthorizationEventPublisher.class)
    AuthorizationEventPublisher authorizationEventPort(
            TransactionalOutbox outbox,
            Clock clock) {
        return new TransactionalOutboxAuthorizationEventPublisher(outbox, clock);
    }

    /**
     * 方法 `gatewayDefinitionStatusService` 按照 `Rbac3PlatformIntegrationConfiguration` 的职责处理输入，完成 `gateway Definition Status Service` 操作并返回结果或产生声明的副作用；调用方应遵守参数和异常契约。
     * Method `gatewayDefinitionStatusService` processes its inputs according to `Rbac3PlatformIntegrationConfiguration`'s responsibility, performs the `gateway Definition Status Service` operation, and returns a result or declared side effect; callers must follow its parameter and exception contract.
     *
     * 用法：调用 `gatewayDefinitionStatusService` 前准备符合契约的参数，并根据返回值、异常或副作用继续业务流程。
     * Usage: provide contract-compliant arguments before calling `gatewayDefinitionStatusService`, then continue the business flow using its result, exception, or side effect.
     *
     * @param state 输入参数 `state`，用于确定本次操作的范围或内容；input value used to determine the operation's scope or content.
     * @param properties 输入参数 `properties`，用于确定本次操作的范围或内容；input value used to determine the operation's scope or content.
     * @return 操作产生的结果，其具体语义由返回类型和所属 API 定义；the result of the operation, whose exact semantics are defined by the return type and owning API.
     */
    @Bean
    @ConditionalOnProperty(prefix = "egon.cola.component.yuheng.reporting",
            name = "enabled", havingValue = "true")
    GatewayDefinitionStatusRepository gatewayDefinitionStatusService(
            GatewayReportingState state,
            GatewayReportingProperties properties) {
        return new GatewayDefinitionStatusRepository(state, properties);
    }

    /** Preserves the public status structure without inferring Cilium routing from retired provider leases. */
    @Bean
    @Primary
    ControlPlaneRuntimeStatusPort rbac3ControlPlaneRuntimeStatusPort(
            ObjectProvider<GatewayDefinitionStatusRepository> definitions,
            ObjectProvider<DdcConfigClientStatusRepository> configStatus,
            Rbac3OperationalRuntimeStatusService operationalStatus,
            Clock clock) {
        return () -> {
            GatewayDefinitionStatusRepository availableDefinition = definitions.getIfAvailable();
            DefinitionStatusVO definition = new DefinitionStatusVO(
                    "UNKNOWN", null, List.of("CONTROL_PLANE_DISABLED"));
            if (availableDefinition != null) {
                var observed = availableDefinition.status();
                definition = new DefinitionStatusVO(observed.status(), observed.definitionSetId(), observed.warnings());
            }
            var operational = operationalStatus.status();
            DdcConfigClientStatusRepository nativeConfig = configStatus.getIfAvailable();
            return new RuntimeStatusVO(
                    nativeConfig == null ? DdcConfigClientStatusVO.unknown() : nativeConfig.status(),
                    definition,
                    new ProviderLeaseStatusVO("STOPPED", null, null),
                    new GatewayReleaseStatusVO(null, "UNKNOWN", null),
                    operational.flyway(), operational.redisProjection(), operational.fence(),
                    operational.outbox(), clock.instant());
        };
    }

    /** Workload readiness follows local prerequisites and the actual native configuration probe, not Gateway publication. */
    @Bean("rbac3Readiness")
    Rbac3ReadinessIndicator rbac3ReadinessIndicator(
            @Qualifier(Rbac3FlywayConfiguration.TIANQUAN_JIANSHEN_FLYWAY) Flyway rbac3Flyway,
            @Qualifier("outboxSchemaMetadataValidator") top.egon.cola.component.outbox.persistence.OutboxSchemaMetadataValidator outboxSchema,
            EntityManagerFactory entityManagerFactory,
            TransactionalOutbox outbox,
            EntityManager entityManager,
            ObjectProvider<DdcConfigClientStatusRepository> ddcConfigStatus,
            @Qualifier("rbac3ControlPlaneRuntimeStatusPort") ControlPlaneRuntimeStatusPort runtimeStatus,
            org.springframework.core.env.Environment environment,
            @Qualifier("tianquanSecurityAuditReady") ObjectProvider<java.util.function.BooleanSupplier> auditReady) {
        String deploymentEnvironment = environment.getProperty("egon.cola.component.rpc.identity.env", "");
        boolean production = !List.of("local", "test").contains(deploymentEnvironment.toLowerCase(java.util.Locale.ROOT));
        return new Rbac3ReadinessIndicator(List.of(
                new ReadinessCheckVO("oauthAudit", () -> auditReady.getIfAvailable(() -> () -> false).getAsBoolean()),
                new ReadinessCheckVO("rbac3Flyway", () -> migrated(rbac3Flyway)),
                new ReadinessCheckVO("outboxManagedSchema", () -> { outboxSchema.validate(); return true; }),
                new ReadinessCheckVO("jpa", entityManagerFactory::isOpen),
                new ReadinessCheckVO("outboxSchema", () -> outbox != null),
                new ReadinessCheckVO("rbac3RuntimePostgresql", () -> {
                    entityManager.createNativeQuery("select count(*) from rbac3_catalog_runtime_projection").getSingleResult();
                    return true;
                }),
                new ReadinessCheckVO("ddcConfigClient", () -> !production || ddcConfigReady(ddcConfigStatus))),
                () -> runtimeStatus.status().gatewayRelease().status());
    }

    /**
     * 方法 `rbac3TrafficDrainListener` 按照 `Rbac3PlatformIntegrationConfiguration` 的职责处理输入，完成 `rbac3 Traffic Drain Listener` 操作并返回结果或产生声明的副作用；调用方应遵守参数和异常契约。
     * Method `rbac3TrafficDrainListener` processes its inputs according to `Rbac3PlatformIntegrationConfiguration`'s responsibility, performs the `rbac3 Traffic Drain Listener` operation, and returns a result or declared side effect; callers must follow its parameter and exception contract.
     *
     * 用法：调用 `rbac3TrafficDrainListener` 前准备符合契约的参数，并根据返回值、异常或副作用继续业务流程。
     * Usage: provide contract-compliant arguments before calling `rbac3TrafficDrainListener`, then continue the business flow using its result, exception, or side effect.
     *
     * @param readiness 输入参数 `readiness`，用于确定本次操作的范围或内容；input value used to determine the operation's scope or content.
     * @return 操作产生的结果，其具体语义由返回类型和所属 API 定义；the result of the operation, whose exact semantics are defined by the return type and owning API.
     */
    @Bean
    @ConditionalOnBean(name = "rbac3Readiness")
    ApplicationListener<ContextClosedEvent> rbac3TrafficDrainListener(
            @Qualifier("rbac3Readiness") Rbac3ReadinessIndicator readiness) {
        return ignored -> readiness.stopAcceptingTraffic();
    }

    /**
     * 方法 `migrated` 按照 `Rbac3PlatformIntegrationConfiguration` 的职责处理输入，完成 `migrated` 操作并返回结果或产生声明的副作用；调用方应遵守参数和异常契约。
     * Method `migrated` processes its inputs according to `Rbac3PlatformIntegrationConfiguration`'s responsibility, performs the `migrated` operation, and returns a result or declared side effect; callers must follow its parameter and exception contract.
     *
     * 用法：调用 `migrated` 前准备符合契约的参数，并根据返回值、异常或副作用继续业务流程。
     * Usage: provide contract-compliant arguments before calling `migrated`, then continue the business flow using its result, exception, or side effect.
     *
     * @param flyway 输入参数 `flyway`，用于确定本次操作的范围或内容；input value used to determine the operation's scope or content.
     * @return 操作产生的结果，其具体语义由返回类型和所属 API 定义；the result of the operation, whose exact semantics are defined by the return type and owning API.
     */
    private static boolean migrated(Flyway flyway) {
        return flyway.info().pending().length == 0
                && flyway.info().current() != null;
    }

    /** Missing or unavailable native delivery never satisfies production configuration readiness. */
    private static boolean ddcConfigReady(
            ObjectProvider<DdcConfigClientStatusRepository> status) {
        DdcConfigClientStatusRepository available = status.getIfAvailable();
        return available != null && available.ready();
    }
}
