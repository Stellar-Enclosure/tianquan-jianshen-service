package top.egon.cola.platform.tianquan.jianshen.admin.config.security;

import com.fasterxml.jackson.databind.ObjectMapper;
import java.net.URI;
import java.nio.charset.StandardCharsets;
import java.time.Instant;
import java.util.List;
import java.util.Map;
import java.util.Set;
import org.junit.jupiter.api.Test;
import org.springframework.boot.test.context.runner.ApplicationContextRunner;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.context.annotation.Import;
import org.springframework.http.MediaType;
import org.springframework.mock.web.MockServletContext;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.test.context.support.TestPropertySourceUtils;
import org.springframework.test.web.servlet.setup.MockMvcBuilders;
import org.springframework.web.context.support.AnnotationConfigWebApplicationContext;
import org.springframework.web.servlet.config.annotation.EnableWebMvc;
import top.egon.cola.platform.tianquan.jianshen.admin.authorization.runtime.catalog.ExecutionGrantAuthorizationController;
import top.egon.cola.platform.tianquan.jianshen.admin.authorization.runtime.catalog.ExecutionGrantAuthorizationService;
import top.egon.cola.platform.tianquan.jianshen.contract.authorization.ExecutionAuthorizationContract;
import top.egon.cola.platform.tianquan.jianshen.core.rule.Rbac3RuleViolation;
import top.egon.cola.platform.tianquan.jianshen.starter.cache.SingleFlightSnapshotLoader;
import top.egon.cola.platform.tianquan.jianshen.starter.security.Rbac3BearerAuthenticationFilter;
import top.egon.cola.platform.tianquan.shoubing.contract.ServiceIdentityPrincipal;
import top.egon.cola.platform.tianquan.shoubing.contract.ServiceTokenContext;
import top.egon.cola.platform.tianquan.shoubing.starter.security.AccessTokenVerification;
import top.egon.cola.platform.tianquan.shoubing.starter.security.IdpBearerAuthenticationFilter;
import top.egon.cola.platform.tianquan.shoubing.starter.security.ServiceAccessTokenVerifier;
import top.egon.cola.platform.tianquan.shoubing.starter.security.ServiceScopeAuthorization;
import top.egon.cola.platform.tianquan.shoubing.starter.security.UserAccessTokenVerifier;

import static org.junit.jupiter.api.Assertions.*;
import static org.mockito.ArgumentMatchers.*;
import static org.mockito.Mockito.*;
import static org.springframework.security.test.web.servlet.setup.SecurityMockMvcConfigurers.springSecurity;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.post;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.*;

class ExecutionGrantAuthorizationSecurityTest {
    private static final String ID = "9" + "1".repeat(62);
    private static final String SECRET = "ENC:v1:key:nonce:secret-sentinel";
    private static final URI ISSUER = URI.create("https://idp.example/tenants/20");
    private static final Instant NOW = Instant.parse("2026-10-29T00:00:00Z");
    private static final ExecutionAuthorizationContract.Request REQUEST = new ExecutionAuthorizationContract.Request("tianji", ID, SECRET);
    private static final ExecutionAuthorizationContract.Decision DECISION = new ExecutionAuthorizationContract.Decision(ID,
            ISSUER.toString(), "20", "alice", "https://api.example/tianji", "TIANJI_AGENT_RUN_EXECUTION",
            "00000000-0000-0000-0000-000000000123", "c".repeat(64), true, NOW.plusSeconds(600), NOW.plusSeconds(30), 2, 3);

    @Test void endpoint_is_disabled_without_explicit_configuration() {
        new ApplicationContextRunner().withUserConfiguration(ExecutionGrantAuthorizationController.class)
                .run(context -> assertTrue(context.getBeansOfType(ExecutionGrantAuthorizationController.class).isEmpty()));
    }

    @Test void actual_internal_security_chain_requires_a_verified_scoped_service() throws Exception {
        try (var context = context()) {
            var verifier = context.getBean(ServiceAccessTokenVerifier.class);
            var owner = context.getBean(ExecutionGrantAuthorizationService.class);
            var good = principal(Set.of(ExecutionAuthorizationContract.SERVICE_SCOPE));
            var noScope = principal(Set.of("other:scope"));
            when(verifier.verify("good-service")).thenReturn(new AccessTokenVerification.Valid<>(good, good.scopes(), null, ISSUER));
            when(verifier.verify("scope-missing")).thenReturn(new AccessTokenVerification.Valid<>(noScope, noScope.scopes(), null, ISSUER));
            when(owner.decide(eq(good), eq(ISSUER), eq(REQUEST))).thenReturn(DECISION);
            var mvc = MockMvcBuilders.webAppContextSetup(context).apply(springSecurity()).build();
            String json = new ObjectMapper().writeValueAsString(REQUEST);
            mvc.perform(post(ExecutionAuthorizationContract.PATH).contentType(MediaType.APPLICATION_JSON).content(json))
                    .andExpect(status().isUnauthorized());
            var missingScope = mvc.perform(post(ExecutionAuthorizationContract.PATH).header("Authorization", "Bearer scope-missing")
                    .contentType(MediaType.APPLICATION_JSON).content(json)).andExpect(status().isForbidden()).andReturn().getResponse();
            assertFalse(missingScope.getContentAsString().contains("\"error\":\"access_denied\""));
            mvc.perform(post(ExecutionAuthorizationContract.PATH).header("Authorization", "Bearer good-service")
                    .contentType(MediaType.APPLICATION_JSON).content(json)).andExpect(status().isOk())
                    .andExpect(header().string("Cache-Control", "no-store")).andExpect(jsonPath("$.grantId").value(ID));
            verify(owner, times(1)).decide(good, ISSUER, REQUEST);
            verify(context.getBean(top.egon.cola.platform.tianquan.jianshen.starter.permission.PermissionExecutionGuard.class))
                    .requireServiceApi("tianquan-jianshen.api.runtime.executionGrant", good);
            assertNull(org.springframework.security.core.context.SecurityContextHolder.getContext().getAuthentication());
        }
    }

    @Test void unavailable_compiled_service_policy_returns_unavailable_before_owner_call() throws Exception {
        try (var context = context()) {
            var verifier = context.getBean(ServiceAccessTokenVerifier.class);
            var guard = context.getBean(top.egon.cola.platform.tianquan.jianshen.starter.permission.PermissionExecutionGuard.class);
            var good = principal(Set.of(ExecutionAuthorizationContract.SERVICE_SCOPE));
            when(verifier.verify("good-service")).thenReturn(new AccessTokenVerification.Valid<>(good, good.scopes(), null, ISSUER));
            doThrow(new top.egon.cola.platform.tianquan.jianshen.starter.client.Rbac3AuthorizationClient.AuthorizationUnavailableException("unavailable"))
                    .when(guard).requireServiceApi("tianquan-jianshen.api.runtime.executionGrant", good);
            var mvc = MockMvcBuilders.webAppContextSetup(context).apply(springSecurity()).build();
            mvc.perform(post(ExecutionAuthorizationContract.PATH).header("Authorization", "Bearer good-service")
                    .contentType(MediaType.APPLICATION_JSON).content(new ObjectMapper().writeValueAsString(REQUEST)))
                    .andExpect(status().isServiceUnavailable()).andExpect(header().string("Cache-Control", "no-store"));
            verifyNoInteractions(context.getBean(ExecutionGrantAuthorizationService.class));
        }
    }

    @Test void malformed_or_oversized_ticket_is_not_forwarded_or_reflected() throws Exception {
        try (var context = context()) {
            var verifier = context.getBean(ServiceAccessTokenVerifier.class); var owner = context.getBean(ExecutionGrantAuthorizationService.class);
            var good = principal(Set.of(ExecutionAuthorizationContract.SERVICE_SCOPE));
            when(verifier.verify("good-service")).thenReturn(new AccessTokenVerification.Valid<>(good, good.scopes(), null, ISSUER));
            var mvc = MockMvcBuilders.webAppContextSetup(context).apply(springSecurity()).build();
            String valid = new ObjectMapper().writeValueAsString(REQUEST);
            for (String bad : List.of(valid + "{}", valid.replace("\"ciphertext\":", "\"ciphertext\":\"" + SECRET + "\",\"ciphertext\":"),
                    valid.replace("\"grantId\":\"" + ID + "\"", "\"grantId\":" + ID),
                    valid.substring(0, valid.length()-1) + ",\"tenantId\":\"20\"}", "null")) {
                var response = mvc.perform(post(ExecutionAuthorizationContract.PATH).header("Authorization", "Bearer good-service")
                        .contentType(MediaType.APPLICATION_JSON).content(bad)).andExpect(status().isBadRequest()).andReturn().getResponse();
                assertFalse(response.getContentAsString().contains(SECRET)); assertEquals("no-store", response.getHeader("Cache-Control"));
            }
            mvc.perform(post(ExecutionAuthorizationContract.PATH).header("Authorization", "Bearer good-service")
                    .contentType(MediaType.APPLICATION_JSON).content(new byte[ExecutionAuthorizationContract.MAX_REQUEST_BYTES + 1]))
                    .andExpect(status().isPayloadTooLarge());
            mvc.perform(post(ExecutionAuthorizationContract.PATH).header("Authorization", "Bearer good-service")
                    .contentType(MediaType.TEXT_PLAIN).content("{}")) .andExpect(status().isUnsupportedMediaType());
            mvc.perform(post(ExecutionAuthorizationContract.PATH).header("Authorization", "Bearer good-service")
                    .header("Content-Type", "application/json", "text/plain").content("{}")) .andExpect(status().isUnsupportedMediaType());
            verifyNoInteractions(owner);
        }
    }

    @Test void denial_and_unavailability_remain_distinct_without_sensitive_error_details() throws Exception {
        try (var context = context()) {
            var verifier = context.getBean(ServiceAccessTokenVerifier.class); var owner = context.getBean(ExecutionGrantAuthorizationService.class);
            var good = principal(Set.of(ExecutionAuthorizationContract.SERVICE_SCOPE));
            when(verifier.verify("good-service")).thenReturn(new AccessTokenVerification.Valid<>(good, good.scopes(), null, ISSUER));
            when(owner.decide(eq(good), eq(ISSUER), eq(REQUEST))).thenThrow(new Rbac3RuleViolation("EXECUTION_GRANT_DENIED"),
                    new Rbac3RuleViolation("APPLICATION_BINDING_DENIED"),
                    new Rbac3RuleViolation("AUTH_RUNTIME_EXECUTION_UNAVAILABLE"),
                    new org.springframework.dao.DataAccessResourceFailureException(SECRET), new IllegalStateException(SECRET));
            var mvc = MockMvcBuilders.webAppContextSetup(context).apply(springSecurity()).build();
            String json = new ObjectMapper().writeValueAsString(REQUEST);
            int iteration = 0;
            for (int expected : new int[]{403, 403, 503, 503, 500}) {
                var response = mvc.perform(post(ExecutionAuthorizationContract.PATH).header("Authorization", "Bearer good-service")
                        .contentType(MediaType.APPLICATION_JSON).content(json.getBytes(StandardCharsets.UTF_8))).andReturn().getResponse();
                assertEquals(expected, response.getStatus()); assertEquals("no-store", response.getHeader("Cache-Control"));
                assertFalse(response.getContentAsString().contains(SECRET));
                if (iteration++ == 1) assertTrue(response.getContentAsString().contains("service_binding_denied"));
            }
        }
    }

    private static AnnotationConfigWebApplicationContext context() {
        var context = new AnnotationConfigWebApplicationContext(); context.setServletContext(new MockServletContext());
        TestPropertySourceUtils.addInlinedPropertiesToEnvironment(context, "egon.tianquan-jianshen.execution-grants.enabled=true");
        context.register(Rbac3AdminSecurityConfiguration.class, Fixture.class); context.refresh(); return context;
    }

    private static ServiceIdentityPrincipal principal(Set<String> scopes) {
        Instant now = Instant.now();
        return new ServiceIdentityPrincipal("tianji", "20", "tianji", "123", URI.create("https://api.example/jianshen"), 1L,
                scopes, "platform", "tianji", "test", "credential", now.minusSeconds(5), now.plusSeconds(300), "tianji", ServiceTokenContext.TENANT);
    }

    @Configuration(proxyBeanMethods = false)
    @EnableWebSecurity
    @EnableWebMvc
    @Import(ExecutionGrantAuthorizationController.class)
    static class Fixture {
        @Bean("jacksonObjectMapper") ObjectMapper mapper() { return new ObjectMapper().findAndRegisterModules(); }
        @Bean ExecutionGrantAuthorizationService executionService() { return mock(ExecutionGrantAuthorizationService.class); }
        @Bean("serviceScopeAuthorization") ServiceScopeAuthorization scope() { return new ServiceScopeAuthorization(); }
        @Bean top.egon.cola.platform.tianquan.jianshen.starter.permission.PermissionExecutionGuard compiledGuard() {
            var guard = mock(top.egon.cola.platform.tianquan.jianshen.starter.permission.PermissionExecutionGuard.class);
            var resource = new top.egon.cola.platform.tianquan.jianshen.contract.permission.PermissionManifest.ResourceDefinition(
                    "tianquan-jianshen.api.runtime.executionGrant", top.egon.cola.platform.tianquan.jianshen.contract.permission.ResourceType.API,
                    Map.of("methods", List.of("POST"), "paths", List.of(ExecutionAuthorizationContract.PATH)),
                    top.egon.cola.platform.tianquan.jianshen.contract.permission.ResourceAccess.PROTECTED, null, null,
                    List.of(top.egon.cola.platform.tianquan.jianshen.contract.permission.PermissionManifest.PrincipalType.SERVICE),
                    List.of(ExecutionAuthorizationContract.SERVICE_SCOPE),
                    new top.egon.cola.platform.tianquan.jianshen.contract.permission.PermissionManifest.I18nReference("permission.runtime", "executionGrant"),
                    top.egon.cola.platform.tianquan.jianshen.contract.permission.DefinitionLifecycle.ACTIVE);
            when(guard.resource("tianquan-jianshen.api.runtime.executionGrant",
                    top.egon.cola.platform.tianquan.jianshen.contract.permission.ResourceType.API)).thenReturn(resource);
            return guard;
        }
        @Bean
        @org.springframework.context.annotation.Role(org.springframework.beans.factory.config.BeanDefinition.ROLE_INFRASTRUCTURE)
        static org.springframework.security.authorization.method.AuthorizationManagerBeforeMethodInterceptor compiledInterceptor(
                top.egon.cola.platform.tianquan.jianshen.starter.permission.PermissionExecutionGuard guard) {
            var manager = new top.egon.cola.platform.tianquan.jianshen.starter.security.Rbac3MethodAuthorizationManager(
                    mock(top.egon.cola.platform.tianquan.jianshen.starter.authorization.AuthorizationService.class), guard);
            var pointcut = new org.springframework.aop.support.StaticMethodMatcherPointcut() {
                @Override public boolean matches(java.lang.reflect.Method method, Class<?> targetClass) { return manager.supports(method, targetClass); }
            };
            var interceptor = new org.springframework.security.authorization.method.AuthorizationManagerBeforeMethodInterceptor(pointcut, manager);
            interceptor.setOrder(org.springframework.security.authorization.method.AuthorizationInterceptorsOrder.PRE_AUTHORIZE.getOrder() + 1);
            return interceptor;
        }
        @Bean UserAccessTokenVerifier users() { return mock(UserAccessTokenVerifier.class); }
        @Bean ServiceAccessTokenVerifier services() { return mock(ServiceAccessTokenVerifier.class); }
        @Bean("idpBearerAuthenticationFilter") IdpBearerAuthenticationFilter idp(Rbac3AdminSecurityConfiguration config, ObjectMapper mapper,
                UserAccessTokenVerifier users, ServiceAccessTokenVerifier services) {
            return new IdpBearerAuthenticationFilter(users, services, config.rbac3EndpointAuthenticationPolicy(), mapper);
        }
        @Bean SingleFlightSnapshotLoader loader() { return mock(SingleFlightSnapshotLoader.class); }
        @Bean("rbac3BearerAuthenticationFilter") Rbac3BearerAuthenticationFilter rbac(ObjectMapper mapper, SingleFlightSnapshotLoader loader) {
            return new Rbac3BearerAuthenticationFilter(loader, mapper);
        }
    }
}
