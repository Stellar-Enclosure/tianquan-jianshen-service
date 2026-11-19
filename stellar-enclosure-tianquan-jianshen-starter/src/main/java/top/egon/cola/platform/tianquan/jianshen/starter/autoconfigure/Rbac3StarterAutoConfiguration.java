package top.egon.cola.platform.tianquan.jianshen.starter.autoconfigure;

import org.springframework.boot.validation.autoconfigure.ValidationAutoConfiguration;
import org.springframework.context.annotation.Import;
import org.springframework.context.annotation.Configuration;
import org.springframework.context.annotation.ComponentScan;
import jakarta.validation.Validator;
import top.egon.cola.platform.tianquan.jianshen.starter.field.FieldWriteAuthorizationConverter;
import top.egon.cola.platform.tianquan.jianshen.starter.field.Rbac3FieldWriteAuthorizationComponent;
import com.fasterxml.jackson.databind.ObjectMapper;
import org.springframework.aop.support.StaticMethodMatcherPointcut;
import org.springframework.beans.factory.annotation.Qualifier;
import org.springframework.beans.factory.ObjectProvider;
import org.springframework.boot.autoconfigure.AutoConfiguration;
import org.springframework.boot.autoconfigure.AutoConfigureAfter;
import org.springframework.boot.autoconfigure.condition.ConditionalOnBean;
import org.springframework.boot.autoconfigure.condition.ConditionalOnMissingBean;
import org.springframework.boot.autoconfigure.condition.ConditionalOnProperty;
import org.springframework.boot.context.properties.EnableConfigurationProperties;
import org.springframework.boot.web.servlet.FilterRegistrationBean;
import org.springframework.context.annotation.Bean;
import org.springframework.security.core.Authentication;
import org.springframework.security.authorization.method.AuthorizationManagerBeforeMethodInterceptor;
import org.springframework.security.core.context.SecurityContextHolder;
import top.egon.cola.component.common.desensitize.strategy.SensitiveStrategyRegistry;
import top.egon.cola.platform.tianquan.shoubing.starter.autoconfigure.IdpStarterAutoConfiguration;
import top.egon.cola.platform.tianquan.shoubing.starter.autoconfigure.IdpStarterProperties;
import top.egon.cola.platform.tianquan.shoubing.starter.client.IdpServiceOAuth2Client;
import top.egon.cola.platform.tianquan.shoubing.starter.client.IdpTransportBindingRegistry;
import top.egon.cola.platform.tianquan.shoubing.starter.security.IdpJwtVerifier;
import top.egon.cola.platform.tianquan.jianshen.starter.authorization.AuthorizationService;
import top.egon.cola.platform.tianquan.jianshen.starter.authorization.DefaultAuthorizationService;
import top.egon.cola.platform.tianquan.jianshen.starter.authorization.Rbac3AboutService;
import top.egon.cola.platform.tianquan.jianshen.starter.cache.AuthorizationSnapshotCache;
import top.egon.cola.platform.tianquan.jianshen.starter.cache.SingleFlightSnapshotLoader;
import top.egon.cola.platform.tianquan.jianshen.starter.cache.AuthorizationSnapshotLoader;
import top.egon.cola.platform.tianquan.jianshen.starter.client.HttpRbac3AuthorizationClient;
import top.egon.cola.platform.tianquan.jianshen.starter.client.HttpTenantServiceTokenSupplier;
import top.egon.cola.platform.tianquan.jianshen.starter.client.Rbac3AuthorizationClient;
import top.egon.cola.platform.tianquan.jianshen.starter.event.Rbac3AuthorizationInvalidationConsumer;
import top.egon.cola.platform.tianquan.jianshen.starter.security.Rbac3BearerAuthenticationFilter;
import top.egon.cola.platform.tianquan.jianshen.starter.security.Rbac3ContextAuthentication;
import top.egon.cola.platform.tianquan.jianshen.starter.security.CurrentRbac3User;
import top.egon.cola.platform.tianquan.jianshen.starter.security.Rbac3MethodAuthorizationManager;
import top.egon.cola.platform.tianquan.jianshen.starter.field.Rbac3FieldJacksonModule;
import top.egon.cola.platform.tianquan.jianshen.starter.web.Rbac3AuthorizationExceptionHandler;

import java.net.URI;
import java.time.Clock;
import java.util.Arrays;
import java.util.List;
import java.util.Set;
import java.util.stream.Collectors;

/**
 * 类型 `Rbac3StarterAutoConfiguration` 位于当前包内，是类型，用于承载 `Rbac3 Starter Auto Configuration` 相关的职责、状态或契约；调用方通常通过其公开 API、Spring 装配或实现关系使用。
 * Type `Rbac3StarterAutoConfiguration` is a type in its package and carries the responsibility, state, or contract for `Rbac3 Starter Auto Configuration`; callers normally use it through its public API, Spring assembly, or implementation relationship.
 *
 * 语义与用法：将 `Rbac3StarterAutoConfiguration` 作为 `当前包` 的职责边界使用，优先依赖其已有构造、接口或 Spring 装配方式。
 * Semantics and usage: use `Rbac3StarterAutoConfiguration` as the responsibility boundary of `the current package`, following its existing construction, interface, or Spring-assembly mechanism.
 */
@AutoConfiguration
@AutoConfigureAfter({IdpStarterAutoConfiguration.class, ValidationAutoConfiguration.class})
@Import(Rbac3StarterAutoConfiguration.FieldWriteConfiguration.class)
@EnableConfigurationProperties(Rbac3StarterProperties.class)
@ConditionalOnProperty(
        prefix = "egon.cola.platform.tianquan.jianshen",
        name = "enabled",
        havingValue = "true")
public class Rbac3StarterAutoConfiguration {

    /** Provides the request-scoped current USER accessor used by services. */
    @Bean
    @ConditionalOnMissingBean
    public CurrentRbac3User currentRbac3User() {
        return new CurrentRbac3User();
    }

    @Bean
    @ConditionalOnMissingBean
    public top.egon.cola.platform.tianquan.jianshen.starter.permission.PermissionPolicyRegistry permissionPolicyRegistry(
            Rbac3StarterProperties properties, @Qualifier("rbac3Clock") Clock clock) {
        return top.egon.cola.platform.tianquan.jianshen.starter.permission.PermissionPolicyRegistry.load(
                new ObjectMapper().findAndRegisterModules(),
                properties.getRuntime().getArtifactDigest(), clock, properties.getRuntime().getCatalogScopes(),
                properties.getRuntime().getBootstrapServiceResourceKeys(), properties.getRuntime().getAnonymousResourceKeys());
    }

    @Bean
    @ConditionalOnMissingBean
    public top.egon.cola.platform.tianquan.jianshen.starter.permission.CurrentEffectivePermissionView currentEffectivePermissionView(
            CurrentRbac3User users, top.egon.cola.platform.tianquan.jianshen.starter.permission.PermissionPolicyRegistry policies,
            @Qualifier("rbac3Clock") Clock clock) {
        return new top.egon.cola.platform.tianquan.jianshen.starter.permission.CurrentEffectivePermissionView(users, policies, clock);
    }

    @Bean
    @ConditionalOnMissingBean
    public top.egon.cola.platform.tianquan.jianshen.starter.permission.PermissionFieldCatalog permissionFieldCatalog(
            top.egon.cola.platform.tianquan.jianshen.starter.permission.PermissionPolicyRegistry policies,
            top.egon.cola.platform.tianquan.jianshen.starter.permission.CurrentEffectivePermissionView views,
            CurrentRbac3User users) {
        return new top.egon.cola.platform.tianquan.jianshen.starter.permission.PermissionFieldCatalog(policies, views, users);
    }

    @Bean
    @ConditionalOnMissingBean
    public top.egon.cola.platform.tianquan.jianshen.starter.permission.PermissionAnonymousBoundary permissionAnonymousBoundary(
            top.egon.cola.platform.tianquan.jianshen.starter.permission.PermissionPolicyRegistry registry,
            ObjectProvider<top.egon.cola.platform.tianquan.shoubing.starter.security.IdpEndpointAuthenticationPolicy> endpointPolicy) {
        return new top.egon.cola.platform.tianquan.jianshen.starter.permission.PermissionAnonymousBoundary(registry, endpointPolicy::getIfAvailable);
    }

    @Bean(name = "permissionDenialAudit")
    @ConditionalOnMissingBean
    public top.egon.cola.platform.tianquan.jianshen.starter.permission.PermissionDenialAudit permissionDenialAuditWithDiagnostics(
            ObjectProvider<top.egon.cola.platform.tianquan.shoubing.starter.security.IdpObservedVerificationComponent> observations,
            org.springframework.context.ApplicationEventPublisher events, @Qualifier("rbac3Clock") Clock clock) {
        return new top.egon.cola.platform.tianquan.jianshen.starter.permission.PermissionDenialAudit(
                observations::getIfAvailable, events::publishEvent, clock);
    }

    /** Retains the former direct factory signature for existing callers. */
    @Deprecated(since = "0.0.1", forRemoval = false)
    public top.egon.cola.platform.tianquan.jianshen.starter.permission.PermissionDenialAudit permissionDenialAudit(
            ObjectProvider<top.egon.cola.platform.tianquan.shoubing.starter.security.IdpObservedVerificationComponent> observations) {
        return new top.egon.cola.platform.tianquan.jianshen.starter.permission.PermissionDenialAudit(observations::getIfAvailable);
    }

    @Bean
    @ConditionalOnMissingBean
    public top.egon.cola.platform.tianquan.jianshen.starter.permission.PermissionServicePolicyGuard permissionServicePolicyGuard(
            top.egon.cola.platform.tianquan.jianshen.starter.permission.PermissionPolicyRegistry registry,
            Rbac3AuthorizationClient client, Rbac3StarterProperties properties, @Qualifier("rbac3Clock") Clock clock) {
        return new top.egon.cola.platform.tianquan.jianshen.starter.permission.PermissionServicePolicyGuard(
                registry, client, properties.getSystemCode(), clock);
    }

    @Bean
    @ConditionalOnMissingBean
    public top.egon.cola.platform.tianquan.jianshen.starter.permission.PermissionExecutionGuard permissionExecutionGuard(
            top.egon.cola.platform.tianquan.jianshen.starter.permission.PermissionPolicyRegistry registry,
            CurrentRbac3User users, AuthorizationSnapshotLoader snapshots,
            top.egon.cola.platform.tianquan.jianshen.starter.permission.PermissionServicePolicyGuard services,
            Rbac3StarterProperties properties,
            top.egon.cola.platform.tianquan.jianshen.starter.permission.PermissionDenialAudit audit,
            top.egon.cola.platform.tianquan.jianshen.starter.permission.PermissionAnonymousBoundary anonymous) {
        return new top.egon.cola.platform.tianquan.jianshen.starter.permission.PermissionExecutionGuard(
                registry, users, snapshots, services, properties.getUserScopePolicy(), audit, anonymous,
                properties.getServiceAnyScopeResources());
    }

    @Bean
    @ConditionalOnMissingBean
    public top.egon.cola.platform.tianquan.jianshen.starter.field.PermissionFieldBindingGuard permissionFieldBindingGuard(
            top.egon.cola.platform.tianquan.jianshen.starter.permission.PermissionPolicyRegistry registry, CurrentRbac3User users,
            ObjectProvider<top.egon.cola.platform.tianquan.jianshen.starter.permission.PermissionServicePolicyGuard> services,
            Rbac3StarterProperties properties,
            top.egon.cola.platform.tianquan.jianshen.starter.permission.PermissionDenialAudit audit,
            top.egon.cola.platform.tianquan.jianshen.starter.permission.PermissionAnonymousBoundary anonymous) {
        return new top.egon.cola.platform.tianquan.jianshen.starter.field.PermissionFieldBindingGuard(
                registry, users, services::getObject, properties.getUserScopePolicy(), audit, anonymous);
    }

    @Bean
    @ConditionalOnMissingBean
    public top.egon.cola.platform.tianquan.jianshen.starter.field.PermissionOutputProjection permissionOutputProjection(
            top.egon.cola.platform.tianquan.jianshen.starter.permission.PermissionExecutionGuard guard, ObjectMapper mapper,
            top.egon.cola.platform.tianquan.jianshen.starter.field.PermissionJsonMapperFactory fields) {
        return new top.egon.cola.platform.tianquan.jianshen.starter.field.PermissionOutputProjection(guard, fields.forTransport(mapper));
    }

    @Bean
    @ConditionalOnMissingBean
    public Rbac3AboutService rbac3AboutService(CurrentRbac3User currentUser) {
        return new Rbac3AboutService(currentUser);
    }

    /** Registers the single response-side Jackson module for RBAC field decisions. */
    @Bean
    @ConditionalOnMissingBean
    public top.egon.cola.platform.tianquan.jianshen.starter.field.PermissionJsonMapperFactory permissionJsonMapperFactory(
            CurrentRbac3User users, ObjectProvider<SensitiveStrategyRegistry> masks,
            top.egon.cola.platform.tianquan.jianshen.starter.permission.PermissionPolicyRegistry policies,
            top.egon.cola.platform.tianquan.jianshen.starter.field.PermissionFieldBindingGuard writes) {
        return new top.egon.cola.platform.tianquan.jianshen.starter.field.PermissionJsonMapperFactory(
                users, masks.getIfAvailable(SensitiveStrategyRegistry::defaults), policies, writes);
    }

    public Rbac3FieldJacksonModule rbac3FieldJacksonModule(
            CurrentRbac3User currentUser,
            ObjectProvider<SensitiveStrategyRegistry> registryProvider,
            top.egon.cola.platform.tianquan.jianshen.starter.permission.PermissionPolicyRegistry policies,
            top.egon.cola.platform.tianquan.jianshen.starter.field.PermissionFieldBindingGuard writes) {
        SensitiveStrategyRegistry registry = registryProvider.getIfAvailable(
                SensitiveStrategyRegistry::defaults);
        return new Rbac3FieldJacksonModule(currentUser, registry, policies, writes);
    }

    /**
     * 方法 `rbac3Clock` 按照 `Rbac3StarterAutoConfiguration` 的职责处理输入，完成 `rbac3 Clock` 操作并返回结果或产生声明的副作用；调用方应遵守参数和异常契约。
     * Method `rbac3Clock` processes its inputs according to `Rbac3StarterAutoConfiguration`'s responsibility, performs the `rbac3 Clock` operation, and returns a result or declared side effect; callers must follow its parameter and exception contract.
     *
     * 用法：调用 `rbac3Clock` 前准备符合契约的参数，并根据返回值、异常或副作用继续业务流程。
     * Usage: provide contract-compliant arguments before calling `rbac3Clock`, then continue the business flow using its result, exception, or side effect.
     *
     * @return 操作产生的结果，其具体语义由返回类型和所属 API 定义；the result of the operation, whose exact semantics are defined by the return type and owning API.
     */
    @Bean
    @ConditionalOnMissingBean(name = "rbac3Clock")
    public Clock rbac3Clock() {
        return Clock.systemUTC();
    }

    /**
     * 方法 `tenantAwareRbac3AuthorizationClient` 按照 `Rbac3StarterAutoConfiguration` 的职责处理输入，完成 `tenant Aware Rbac3 Authorization Client` 操作并返回结果或产生声明的副作用；调用方应遵守参数和异常契约。
     * Method `tenantAwareRbac3AuthorizationClient` processes its inputs according to `Rbac3StarterAutoConfiguration`'s responsibility, performs the `tenant Aware Rbac3 Authorization Client` operation, and returns a result or declared side effect; callers must follow its parameter and exception contract.
     *
     * 用法：调用 `tenantAwareRbac3AuthorizationClient` 前准备符合契约的参数，并根据返回值、异常或副作用继续业务流程。
     * Usage: provide contract-compliant arguments before calling `tenantAwareRbac3AuthorizationClient`, then continue the business flow using its result, exception, or side effect.
     *
     * @param objectMapper 输入参数 `objectMapper`，用于确定本次操作的范围或内容；input value used to determine the operation's scope or content.
     * @param properties 输入参数 `properties`，用于确定本次操作的范围或内容；input value used to determine the operation's scope or content.
     * @return 操作产生的结果，其具体语义由返回类型和所属 API 定义；the result of the operation, whose exact semantics are defined by the return type and owning API.
     */
    @Bean
    @ConditionalOnProperty(
            prefix = "egon.cola.platform.tianquan.jianshen.authorization.service-token",
            name = "enabled",
            havingValue = "true")
    @ConditionalOnMissingBean
    public Rbac3AuthorizationClient tenantAwareRbac3AuthorizationClient(
            ObjectMapper objectMapper,
            Rbac3StarterProperties properties,
            IdpServiceOAuth2Client serviceClient,
            @Qualifier("idpStarterProperties") IdpStarterProperties idpProperties,
            @Qualifier("idpTransportBindingRegistry") ObjectProvider<IdpTransportBindingRegistry> transportBindings) {
        var authorization = properties.getAuthorization();
        var serviceToken = authorization.getServiceToken();
        HttpTenantServiceTokenSupplier credentials =
                new HttpTenantServiceTokenSupplier(
                        serviceClient,
                        idpProperties,
                        URI.create(required(
                                serviceToken.getResourceUri(),
                                "authorization.serviceToken.resourceUri"
                        )),
                        scopes(serviceToken.getScopes())
                );
        URI endpoint = URI.create(required(authorization.getEndpoint(), "authorization.endpoint"));
        if (authorization.isRequireManagedTransport()) {
            return new HttpRbac3AuthorizationClient(endpoint, credentials, authorization.getFetchTimeout(), objectMapper,
                    required(properties.getSystemCode(), "systemCode"), transportBindings.getObject());
        }
        return new HttpRbac3AuthorizationClient(
                endpoint,
                credentials,
                authorization.getFetchTimeout(),
                objectMapper
        );
    }

    /**
     * 方法 `singleFlightSnapshotLoader` 按照 `Rbac3StarterAutoConfiguration` 的职责处理输入，完成 `single Flight Snapshot Loader` 操作并返回结果或产生声明的副作用；调用方应遵守参数和异常契约。
     * Method `singleFlightSnapshotLoader` processes its inputs according to `Rbac3StarterAutoConfiguration`'s responsibility, performs the `single Flight Snapshot Loader` operation, and returns a result or declared side effect; callers must follow its parameter and exception contract.
     *
     * 用法：调用 `singleFlightSnapshotLoader` 前准备符合契约的参数，并根据返回值、异常或副作用继续业务流程。
     * Usage: provide contract-compliant arguments before calling `singleFlightSnapshotLoader`, then continue the business flow using its result, exception, or side effect.
     *
     * @param cache 输入参数 `cache`，用于确定本次操作的范围或内容；input value used to determine the operation's scope or content.
     * @param client 输入参数 `client`，用于确定本次操作的范围或内容；input value used to determine the operation's scope or content.
     * @param properties 输入参数 `properties`，用于确定本次操作的范围或内容；input value used to determine the operation's scope or content.
     * @param clock 输入参数 `clock`，用于确定本次操作的范围或内容；input value used to determine the operation's scope or content.
     * @return 操作产生的结果，其具体语义由返回类型和所属 API 定义；the result of the operation, whose exact semantics are defined by the return type and owning API.
     */
    @Bean(name = {"authorizationSnapshotLoader", "singleFlightSnapshotLoader"})
    @ConditionalOnBean(Rbac3AuthorizationClient.class)
    @ConditionalOnMissingBean(AuthorizationSnapshotLoader.class)
    public SingleFlightSnapshotLoader singleFlightSnapshotLoader(
            Rbac3AuthorizationClient client,
            Rbac3StarterProperties properties,
            @Qualifier("rbac3Clock") Clock clock) {
        return new SingleFlightSnapshotLoader(client, required(properties.getSystemCode(), "systemCode"), clock);
    }

    /**
     * 方法 `rbac3AuthorizationInvalidationConsumer` 按照 `Rbac3StarterAutoConfiguration` 的职责处理输入，完成 `rbac3 Authorization Invalidation Consumer` 操作并返回结果或产生声明的副作用；调用方应遵守参数和异常契约。
     * Method `rbac3AuthorizationInvalidationConsumer` processes its inputs according to `Rbac3StarterAutoConfiguration`'s responsibility, performs the `rbac3 Authorization Invalidation Consumer` operation, and returns a result or declared side effect; callers must follow its parameter and exception contract.
     *
     * 用法：调用 `rbac3AuthorizationInvalidationConsumer` 前准备符合契约的参数，并根据返回值、异常或副作用继续业务流程。
     * Usage: provide contract-compliant arguments before calling `rbac3AuthorizationInvalidationConsumer`, then continue the business flow using its result, exception, or side effect.
     *
     * @param cache 输入参数 `cache`，用于确定本次操作的范围或内容；input value used to determine the operation's scope or content.
     * @param properties 输入参数 `properties`，用于确定本次操作的范围或内容；input value used to determine the operation's scope or content.
     * @return 操作产生的结果，其具体语义由返回类型和所属 API 定义；the result of the operation, whose exact semantics are defined by the return type and owning API.
     */
    @Bean
    @ConditionalOnBean(AuthorizationSnapshotCache.class)
    @ConditionalOnMissingBean
    public Rbac3AuthorizationInvalidationConsumer
            rbac3AuthorizationInvalidationConsumer(
                    AuthorizationSnapshotCache cache,
                    Rbac3StarterProperties properties) {
        return new Rbac3AuthorizationInvalidationConsumer(
                required(properties.getSystemCode(), "systemCode"), cache);
    }

    /**
     * 方法 `rbac3RuntimeContextSource` 按照 `Rbac3StarterAutoConfiguration` 的职责处理输入，完成 `rbac3 Runtime Context Source` 操作并返回结果或产生声明的副作用；调用方应遵守参数和异常契约。
     * Method `rbac3RuntimeContextSource` processes its inputs according to `Rbac3StarterAutoConfiguration`'s responsibility, performs the `rbac3 Runtime Context Source` operation, and returns a result or declared side effect; callers must follow its parameter and exception contract.
     *
     * 用法：调用 `rbac3RuntimeContextSource` 前准备符合契约的参数，并根据返回值、异常或副作用继续业务流程。
     * Usage: provide contract-compliant arguments before calling `rbac3RuntimeContextSource`, then continue the business flow using its result, exception, or side effect.
     *
     * @return 操作产生的结果，其具体语义由返回类型和所属 API 定义；the result of the operation, whose exact semantics are defined by the return type and owning API.
     */
    @Bean
    @ConditionalOnMissingBean
    public AuthorizationService.RuntimeContextSource rbac3RuntimeContextSource() {
        return () -> {
            Authentication authentication = SecurityContextHolder.getContext()
                    .getAuthentication();
            if (authentication instanceof Rbac3ContextAuthentication token) {
                return token.context();
            }
            throw new IllegalStateException("Tianquan-Jianshen authentication is required");
        };
    }

    /**
     * 方法 `rbac3OperationSodEvaluator` 按照 `Rbac3StarterAutoConfiguration` 的职责处理输入，完成 `rbac3 Operation Sod Evaluator` 操作并返回结果或产生声明的副作用；调用方应遵守参数和异常契约。
     * Method `rbac3OperationSodEvaluator` processes its inputs according to `Rbac3StarterAutoConfiguration`'s responsibility, performs the `rbac3 Operation Sod Evaluator` operation, and returns a result or declared side effect; callers must follow its parameter and exception contract.
     *
     * 用法：调用 `rbac3OperationSodEvaluator` 前准备符合契约的参数，并根据返回值、异常或副作用继续业务流程。
     * Usage: provide contract-compliant arguments before calling `rbac3OperationSodEvaluator`, then continue the business flow using its result, exception, or side effect.
     *
     * @return 操作产生的结果，其具体语义由返回类型和所属 API 定义；the result of the operation, whose exact semantics are defined by the return type and owning API.
     */
    @Bean
    @ConditionalOnMissingBean
    public AuthorizationService.OperationSodEvaluator rbac3OperationSodEvaluator() {
        return request -> new AuthorizationService.OperationSodResult(
                false, "PARTICIPATION_VERIFIER_UNAVAILABLE", List.of(), List.of());
    }

    /**
     * 方法 `rbac3FenceVerifier` 按照 `Rbac3StarterAutoConfiguration` 的职责处理输入，完成 `rbac3 Fence Verifier` 操作并返回结果或产生声明的副作用；调用方应遵守参数和异常契约。
     * Method `rbac3FenceVerifier` processes its inputs according to `Rbac3StarterAutoConfiguration`'s responsibility, performs the `rbac3 Fence Verifier` operation, and returns a result or declared side effect; callers must follow its parameter and exception contract.
     *
     * 用法：调用 `rbac3FenceVerifier` 前准备符合契约的参数，并根据返回值、异常或副作用继续业务流程。
     * Usage: provide contract-compliant arguments before calling `rbac3FenceVerifier`, then continue the business flow using its result, exception, or side effect.
     *
     * @param clock 输入参数 `clock`，用于确定本次操作的范围或内容；input value used to determine the operation's scope or content.
     * @return 操作产生的结果，其具体语义由返回类型和所属 API 定义；the result of the operation, whose exact semantics are defined by the return type and owning API.
     */
    @Bean
    @ConditionalOnMissingBean
    public AuthorizationService.FenceVerifier rbac3FenceVerifier(
            CurrentRbac3User currentUser, AuthorizationSnapshotLoader snapshots,
            @Qualifier("rbac3Clock") Clock clock) {
        return request -> {
            var current = currentUser.require();
            var before = current.snapshot().permissionSnapshot();
            var fresh = snapshots.load(current.identity());
            var after = fresh.permissionSnapshot();
            boolean same = before != null && after != null && before.issuer().equals(after.issuer())
                    && before.subject().equals(after.subject()) && before.catalogScope().equals(after.catalogScope())
                    && before.catalogVersion().equals(after.catalogVersion()) && before.authVersion().equals(after.authVersion())
                    && before.policyVersion().equals(after.policyVersion()) && before.activeRoleContext().equals(after.activeRoleContext())
                    && fresh.permissions().contains(request.permissionCode())
                    && java.util.Objects.equals(current.snapshot().policyBinding(), fresh.policyBinding());
            return new AuthorizationService.FenceResult(same, same ? "ALLOW" : "AUTHORIZATION_FENCED", clock.instant(), List.of());
        };
    }

    public AuthorizationService.FenceVerifier rbac3FenceVerifier(Clock clock) {
        return request -> new AuthorizationService.FenceResult(false, "FENCE_VERIFIER_UNAVAILABLE", clock.instant(), List.of());
    }

    /**
     * 方法 `authorizationService` 按照 `Rbac3StarterAutoConfiguration` 的职责处理输入，完成 `authorization Service` 操作并返回结果或产生声明的副作用；调用方应遵守参数和异常契约。
     * Method `authorizationService` processes its inputs according to `Rbac3StarterAutoConfiguration`'s responsibility, performs the `authorization Service` operation, and returns a result or declared side effect; callers must follow its parameter and exception contract.
     *
     * 用法：调用 `authorizationService` 前准备符合契约的参数，并根据返回值、异常或副作用继续业务流程。
     * Usage: provide contract-compliant arguments before calling `authorizationService`, then continue the business flow using its result, exception, or side effect.
     *
     * @param contextSource 输入参数 `contextSource`，用于确定本次操作的范围或内容；input value used to determine the operation's scope or content.
     * @param operationSodEvaluator 输入参数 `operationSodEvaluator`，用于确定本次操作的范围或内容；input value used to determine the operation's scope or content.
     * @param fenceVerifier 输入参数 `fenceVerifier`，用于确定本次操作的范围或内容；input value used to determine the operation's scope or content.
     * @param clock 输入参数 `clock`，用于确定本次操作的范围或内容；input value used to determine the operation's scope or content.
     * @return 操作产生的结果，其具体语义由返回类型和所属 API 定义；the result of the operation, whose exact semantics are defined by the return type and owning API.
     */
    @Bean(name = "rbac3AuthorizationDelegate")
    @ConditionalOnMissingBean
    public AuthorizationService rbac3AuthorizationDelegate(
            AuthorizationService.RuntimeContextSource contextSource,
            AuthorizationService.OperationSodEvaluator operationSodEvaluator,
            AuthorizationService.FenceVerifier fenceVerifier,
            @Qualifier("rbac3Clock") Clock clock) {
        return new DefaultAuthorizationService(
                contextSource, operationSodEvaluator, fenceVerifier, clock);
    }

    @Bean(name = "authorizationService")
    @org.springframework.context.annotation.Primary
    @ConditionalOnBean(name = "rbac3AuthorizationDelegate")
    @ConditionalOnMissingBean(name = "authorizationService")
    public AuthorizationService authorizationServiceWithDiagnostics(@Qualifier("rbac3AuthorizationDelegate") AuthorizationService delegate,
            @Qualifier("oauthUsageObservationProperties") org.springframework.beans.factory.ObjectProvider<top.egon.cola.platform.tianquan.shoubing.starter.audit.OAuthUsageObservationProperties> properties,
            @Qualifier("idpSecurityMetricsRecorder") org.springframework.beans.factory.ObjectProvider<top.egon.cola.platform.tianquan.shoubing.core.observability.IdpSecurityMetricsRecorder> metrics,
            @Qualifier("idpObservedVerificationComponent") org.springframework.beans.factory.ObjectProvider<top.egon.cola.platform.tianquan.shoubing.starter.security.IdpObservedVerificationComponent> observations,
            @Qualifier("defaultValidator") org.springframework.beans.factory.ObjectProvider<jakarta.validation.Validator> validators,
            top.egon.cola.platform.tianquan.jianshen.starter.permission.PermissionDenialAudit diagnostic,
            top.egon.cola.platform.tianquan.jianshen.starter.permission.PermissionPolicyRegistry registry) {
        var usage = properties.getIfAvailable();
        if (usage == null || !usage.isEnabled()) { return delegate; }
        return new top.egon.cola.platform.tianquan.jianshen.starter.authorization.Rbac3ObservedAuthorizationService(delegate,
                metrics.getObject(), observations.getObject(), validators.getObject(), diagnostic, registry);
    }

    /** Preserves the former direct factory signature for existing consumers. */
    @Deprecated(since = "0.0.1", forRemoval = false)
    public AuthorizationService authorizationService(AuthorizationService delegate,
            org.springframework.beans.factory.ObjectProvider<top.egon.cola.platform.tianquan.shoubing.starter.audit.OAuthUsageObservationProperties> properties,
            org.springframework.beans.factory.ObjectProvider<top.egon.cola.platform.tianquan.shoubing.core.observability.IdpSecurityMetricsRecorder> metrics,
            org.springframework.beans.factory.ObjectProvider<top.egon.cola.platform.tianquan.shoubing.starter.security.IdpObservedVerificationComponent> observations,
            org.springframework.beans.factory.ObjectProvider<jakarta.validation.Validator> validators) {
        var usage = properties.getIfAvailable();
        if (usage == null || !usage.isEnabled()) return delegate;
        return new top.egon.cola.platform.tianquan.jianshen.starter.authorization.Rbac3ObservedAuthorizationService(delegate,
                metrics.getObject(), observations.getObject(), validators.getObject());
    }

    /** Preserves the former direct factory API for existing non-observed callers. */
    public AuthorizationService authorizationService(AuthorizationService.RuntimeContextSource contextSource,
            AuthorizationService.OperationSodEvaluator operationSodEvaluator, AuthorizationService.FenceVerifier fenceVerifier, Clock clock) {
        return new DefaultAuthorizationService(contextSource, operationSodEvaluator, fenceVerifier, clock);
    }

    /**
     * 方法 `authorizationBootstrapService` 按照 `Rbac3StarterAutoConfiguration` 的职责处理输入，完成 `authorization Bootstrap Service` 操作并返回结果或产生声明的副作用；调用方应遵守参数和异常契约。
     * Method `authorizationBootstrapService` processes its inputs according to `Rbac3StarterAutoConfiguration`'s responsibility, performs the `authorization Bootstrap Service` operation, and returns a result or declared side effect; callers must follow its parameter and exception contract.
     *
     * 用法：调用 `authorizationBootstrapService` 前准备符合契约的参数，并根据返回值、异常或副作用继续业务流程。
     * Usage: provide contract-compliant arguments before calling `authorizationBootstrapService`, then continue the business flow using its result, exception, or side effect.
     *
     * @param contextSource 输入参数 `contextSource`，用于确定本次操作的范围或内容；input value used to determine the operation's scope or content.
     * @return 操作产生的结果，其具体语义由返回类型和所属 API 定义；the result of the operation, whose exact semantics are defined by the return type and owning API.
     */
    /**
     * 方法 `rbac3MethodAuthorizationAspect` 按照 `Rbac3StarterAutoConfiguration` 的职责处理输入，完成 `rbac3 Method Authorization Aspect` 操作并返回结果或产生声明的副作用；调用方应遵守参数和异常契约。
     * Method `rbac3MethodAuthorizationAspect` processes its inputs according to `Rbac3StarterAutoConfiguration`'s responsibility, performs the `rbac3 Method Authorization Aspect` operation, and returns a result or declared side effect; callers must follow its parameter and exception contract.
     *
     * 用法：调用 `rbac3MethodAuthorizationAspect` 前准备符合契约的参数，并根据返回值、异常或副作用继续业务流程。
     * Usage: provide contract-compliant arguments before calling `rbac3MethodAuthorizationAspect`, then continue the business flow using its result, exception, or side effect.
     *
     * @param authorizationService 输入参数 `authorizationService`，用于确定本次操作的范围或内容；input value used to determine the operation's scope or content.
     * @return 操作产生的结果，其具体语义由返回类型和所属 API 定义；the result of the operation, whose exact semantics are defined by the return type and owning API.
     */
    /**
     * Registers the single Spring Method Security interceptor for Tianquan-Jianshen declarations.
     */
    @Bean(name = "rbac3MethodAuthorizationInterceptor")
    @org.springframework.context.annotation.Role(org.springframework.beans.factory.config.BeanDefinition.ROLE_INFRASTRUCTURE)
    @ConditionalOnMissingBean(name = "rbac3MethodAuthorizationInterceptor")
    public AuthorizationManagerBeforeMethodInterceptor
            rbac3MethodAuthorizationInterceptor(
                    AuthorizationService authorizationService,
                    top.egon.cola.platform.tianquan.jianshen.starter.permission.PermissionExecutionGuard compiledPolicy,
                    @org.springframework.beans.factory.annotation.Qualifier("egon.cola.platform.tianquan.jianshen-top.egon.cola.platform.tianquan.jianshen.starter.autoconfigure.Rbac3StarterProperties") Rbac3StarterProperties properties,
                    @org.springframework.beans.factory.annotation.Qualifier("idpObservedVerificationComponent")
                    org.springframework.beans.factory.ObjectProvider<top.egon.cola.platform.tianquan.shoubing.starter.security.IdpObservedVerificationComponent> observations,
                    @org.springframework.beans.factory.annotation.Qualifier("idpSecurityMetricsRecorder")
                    org.springframework.beans.factory.ObjectProvider<top.egon.cola.platform.tianquan.shoubing.core.observability.IdpSecurityMetricsRecorder> metrics,
                    @org.springframework.beans.factory.annotation.Qualifier("defaultValidator")
                    org.springframework.beans.factory.ObjectProvider<jakarta.validation.Validator> validators) {
        Rbac3MethodAuthorizationManager manager = new Rbac3MethodAuthorizationManager(authorizationService, compiledPolicy);
        return methodAuthorizationInterceptor(manager);
    }

    /** Keeps the former direct factory call with its permission-only compatibility policy. */
    public AuthorizationManagerBeforeMethodInterceptor rbac3MethodAuthorizationInterceptor(AuthorizationService authorizationService) {
        return methodAuthorizationInterceptor(new Rbac3MethodAuthorizationManager(authorizationService));
    }

    private AuthorizationManagerBeforeMethodInterceptor methodAuthorizationInterceptor(Rbac3MethodAuthorizationManager manager) {
        StaticMethodMatcherPointcut pointcut = new StaticMethodMatcherPointcut() {
            @Override
            public boolean matches(
                    java.lang.reflect.Method method,
                    Class<?> targetClass) {
                return manager.supports(method, targetClass);
            }
        };
        AuthorizationManagerBeforeMethodInterceptor interceptor = new AuthorizationManagerBeforeMethodInterceptor(pointcut, manager);
        interceptor.setOrder(org.springframework.security.authorization.method.AuthorizationInterceptorsOrder.PRE_AUTHORIZE.getOrder() + 1);
        return interceptor;
    }

    /**
     * 方法 `rbac3AuthorizationExceptionHandler` 按照 `Rbac3StarterAutoConfiguration` 的职责处理输入，完成 `rbac3 Authorization Exception Handler` 操作并返回结果或产生声明的副作用；调用方应遵守参数和异常契约。
     * Method `rbac3AuthorizationExceptionHandler` processes its inputs according to `Rbac3StarterAutoConfiguration`'s responsibility, performs the `rbac3 Authorization Exception Handler` operation, and returns a result or declared side effect; callers must follow its parameter and exception contract.
     *
     * 用法：调用 `rbac3AuthorizationExceptionHandler` 前准备符合契约的参数，并根据返回值、异常或副作用继续业务流程。
     * Usage: provide contract-compliant arguments before calling `rbac3AuthorizationExceptionHandler`, then continue the business flow using its result, exception, or side effect.
     *
     * @return 操作产生的结果，其具体语义由返回类型和所属 API 定义；the result of the operation, whose exact semantics are defined by the return type and owning API.
     */
    @Bean
    @ConditionalOnMissingBean
    public Rbac3AuthorizationExceptionHandler rbac3AuthorizationExceptionHandler() {
        return new Rbac3AuthorizationExceptionHandler();
    }

    /**
     * 方法 `rbac3BearerAuthenticationFilter` 按照 `Rbac3StarterAutoConfiguration` 的职责处理输入，完成 `rbac3 Bearer Authentication Filter` 操作并返回结果或产生声明的副作用；调用方应遵守参数和异常契约。
     * Method `rbac3BearerAuthenticationFilter` processes its inputs according to `Rbac3StarterAutoConfiguration`'s responsibility, performs the `rbac3 Bearer Authentication Filter` operation, and returns a result or declared side effect; callers must follow its parameter and exception contract.
     *
     * 用法：调用 `rbac3BearerAuthenticationFilter` 前准备符合契约的参数，并根据返回值、异常或副作用继续业务流程。
     * Usage: provide contract-compliant arguments before calling `rbac3BearerAuthenticationFilter`, then continue the business flow using its result, exception, or side effect.
     *
     * @param snapshotLoader 输入参数 `snapshotLoader`，用于确定本次操作的范围或内容；input value used to determine the operation's scope or content.
     * @param objectMapper 输入参数 `objectMapper`，用于确定本次操作的范围或内容；input value used to determine the operation's scope or content.
     * @return 操作产生的结果，其具体语义由返回类型和所属 API 定义；the result of the operation, whose exact semantics are defined by the return type and owning API.
     */
    @Bean(name = "rbac3BearerAuthenticationFilter")
    @ConditionalOnBean({IdpJwtVerifier.class, AuthorizationSnapshotLoader.class})
    @ConditionalOnMissingBean
    public Rbac3BearerAuthenticationFilter rbac3BearerAuthenticationFilterWithDiagnostics(
            AuthorizationSnapshotLoader snapshotLoader,
            ObjectMapper objectMapper,
            top.egon.cola.platform.tianquan.jianshen.starter.permission.PermissionDenialAudit diagnostic) {
        return new Rbac3BearerAuthenticationFilter(snapshotLoader, objectMapper, diagnostic);
    }

    @Deprecated(since = "0.0.1", forRemoval = false)
    public Rbac3BearerAuthenticationFilter rbac3BearerAuthenticationFilter(AuthorizationSnapshotLoader snapshotLoader,
                                                                            ObjectMapper objectMapper) {
        return new Rbac3BearerAuthenticationFilter(snapshotLoader, objectMapper);
    }

    /**
     * 方法 `rbac3BearerFilterRegistration` 按照 `Rbac3StarterAutoConfiguration` 的职责处理输入，完成 `rbac3 Bearer Filter Registration` 操作并返回结果或产生声明的副作用；调用方应遵守参数和异常契约。
     * Method `rbac3BearerFilterRegistration` processes its inputs according to `Rbac3StarterAutoConfiguration`'s responsibility, performs the `rbac3 Bearer Filter Registration` operation, and returns a result or declared side effect; callers must follow its parameter and exception contract.
     *
     * 用法：调用 `rbac3BearerFilterRegistration` 前准备符合契约的参数，并根据返回值、异常或副作用继续业务流程。
     * Usage: provide contract-compliant arguments before calling `rbac3BearerFilterRegistration`, then continue the business flow using its result, exception, or side effect.
     *
     * @param filter 输入参数 `filter`，用于确定本次操作的范围或内容；input value used to determine the operation's scope or content.
     * @param properties 输入参数 `properties`，用于确定本次操作的范围或内容；input value used to determine the operation's scope or content.
     * @return 操作产生的结果，其具体语义由返回类型和所属 API 定义；the result of the operation, whose exact semantics are defined by the return type and owning API.
     */
    @Bean
    @ConditionalOnBean(Rbac3BearerAuthenticationFilter.class)
    @ConditionalOnMissingBean(name = "rbac3BearerFilterRegistration")
    public FilterRegistrationBean<Rbac3BearerAuthenticationFilter>
            rbac3BearerFilterRegistration(
                    Rbac3BearerAuthenticationFilter filter,
                    Rbac3StarterProperties properties) {
        FilterRegistrationBean<Rbac3BearerAuthenticationFilter> registration =
                new FilterRegistrationBean<>(filter);
        registration.setName("rbac3BearerAuthenticationFilter");
        registration.setOrder(-101);
        registration.setEnabled(properties.isRegisterFilter());
        return registration;
    }

    @Configuration(value = "rbac3FieldWriteConfiguration", proxyBeanMethods = false)
    @ComponentScan(basePackageClasses = FieldWriteAuthorizationConverter.class)
    static class FieldWriteConfiguration { }

    @Bean(name = "rbac3FieldWriteAuthorizationComponent")
    @ConditionalOnBean(name = {"authorizationService", "currentRbac3User", "defaultValidator"})
    @ConditionalOnMissingBean(Rbac3FieldWriteAuthorizationComponent.class)
    public Rbac3FieldWriteAuthorizationComponent rbac3FieldWriteAuthorizationComponent(
            @Qualifier("authorizationService") AuthorizationService authorization,
            @Qualifier("currentRbac3User") CurrentRbac3User currentUser,
            @Qualifier("fieldWriteAuthorizationConverterImpl") FieldWriteAuthorizationConverter converter,
            @Qualifier("defaultValidator") Validator validator) {
        return new Rbac3FieldWriteAuthorizationComponent(
                authorization, currentUser, converter, validator);
    }

    /**
     * 方法 `required` 按照 `Rbac3StarterAutoConfiguration` 的职责处理输入，完成 `required` 操作并返回结果或产生声明的副作用；调用方应遵守参数和异常契约。
     * Method `required` processes its inputs according to `Rbac3StarterAutoConfiguration`'s responsibility, performs the `required` operation, and returns a result or declared side effect; callers must follow its parameter and exception contract.
     *
     * 用法：调用 `required` 前准备符合契约的参数，并根据返回值、异常或副作用继续业务流程。
     * Usage: provide contract-compliant arguments before calling `required`, then continue the business flow using its result, exception, or side effect.
     *
     * @param value 输入参数 `value`，用于确定本次操作的范围或内容；input value used to determine the operation's scope or content.
     * @param name 输入参数 `name`，用于确定本次操作的范围或内容；input value used to determine the operation's scope or content.
     * @return 操作产生的结果，其具体语义由返回类型和所属 API 定义；the result of the operation, whose exact semantics are defined by the return type and owning API.
     */
    private static String required(String value, String name) {
        if (value == null || value.isBlank()) {
            throw new IllegalArgumentException(name + " is required");
        }
        return value.trim();
    }

    /**
     * 方法 `scopes` 按照 `Rbac3StarterAutoConfiguration` 的职责处理输入，完成 `scopes` 操作并返回结果或产生声明的副作用；调用方应遵守参数和异常契约。
     * Method `scopes` processes its inputs according to `Rbac3StarterAutoConfiguration`'s responsibility, performs the `scopes` operation, and returns a result or declared side effect; callers must follow its parameter and exception contract.
     *
     * 用法：调用 `scopes` 前准备符合契约的参数，并根据返回值、异常或副作用继续业务流程。
     * Usage: provide contract-compliant arguments before calling `scopes`, then continue the business flow using its result, exception, or side effect.
     *
     * @param value 输入参数 `value`，用于确定本次操作的范围或内容；input value used to determine the operation's scope or content.
     * @return 操作产生的结果，其具体语义由返回类型和所属 API 定义；the result of the operation, whose exact semantics are defined by the return type and owning API.
     */
    private static Set<String> scopes(String value) {
        return Arrays.stream(required(
                        value,
                        "authorization.serviceToken.scopes"
                ).split("[,\\s]+"))
                .filter(scope -> !scope.isBlank())
                .collect(Collectors.toUnmodifiableSet());
    }
    /** @deprecated compatibility factory overload for the former loader type. */
    @Deprecated(since = "0.0.1", forRemoval = false)
    public top.egon.cola.platform.tianquan.jianshen.starter.permission.PermissionExecutionGuard permissionExecutionGuard(
            top.egon.cola.platform.tianquan.jianshen.starter.permission.PermissionPolicyRegistry registry,
            CurrentRbac3User users, SingleFlightSnapshotLoader snapshots,
            top.egon.cola.platform.tianquan.jianshen.starter.permission.PermissionServicePolicyGuard services,
            Rbac3StarterProperties properties,
            top.egon.cola.platform.tianquan.jianshen.starter.permission.PermissionDenialAudit audit,
            top.egon.cola.platform.tianquan.jianshen.starter.permission.PermissionAnonymousBoundary anonymous) {
        return permissionExecutionGuard(registry, users, (AuthorizationSnapshotLoader) snapshots, services, properties, audit, anonymous);
    }

    /** @deprecated compatibility factory overload for the former loader type. */
    @Deprecated(since = "0.0.1", forRemoval = false)
    public AuthorizationService.FenceVerifier rbac3FenceVerifier(
            CurrentRbac3User currentUser, SingleFlightSnapshotLoader snapshots,
            @Qualifier("rbac3Clock") Clock clock) {
        return rbac3FenceVerifier(currentUser, (AuthorizationSnapshotLoader) snapshots, clock);
    }

    /** @deprecated compatibility factory overload for the former loader type. */
    @Deprecated(since = "0.0.1", forRemoval = false)
    public Rbac3BearerAuthenticationFilter rbac3BearerAuthenticationFilter(
            SingleFlightSnapshotLoader snapshotLoader,
            ObjectMapper objectMapper) {
        return rbac3BearerAuthenticationFilter((AuthorizationSnapshotLoader) snapshotLoader, objectMapper);
    }

}
