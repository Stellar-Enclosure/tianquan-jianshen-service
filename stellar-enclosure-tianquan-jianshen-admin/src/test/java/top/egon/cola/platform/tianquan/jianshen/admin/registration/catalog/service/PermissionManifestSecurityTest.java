package top.egon.cola.platform.tianquan.jianshen.admin.registration.catalog.service;

import top.egon.cola.platform.tianquan.jianshen.admin.registration.catalog.domain.convertor.PermissionCatalogJson;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.datatype.jsr310.JavaTimeModule;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.context.annotation.Import;
import org.springframework.http.MediaType;
import org.springframework.mock.web.MockServletContext;
import org.springframework.security.config.annotation.method.configuration.EnableMethodSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.core.annotation.AnnotationTemplateExpressionDefaults;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.test.web.servlet.MockMvc;
import org.springframework.test.web.servlet.setup.MockMvcBuilders;
import org.springframework.web.context.support.AnnotationConfigWebApplicationContext;
import org.springframework.web.servlet.config.annotation.EnableWebMvc;
import top.egon.cola.platform.tianquan.jianshen.admin.config.security.PermissionCatalogSecurityConfiguration;
import top.egon.cola.platform.tianquan.jianshen.admin.registration.catalog.controller.PermissionCatalogExceptionHandler;
import top.egon.cola.platform.tianquan.jianshen.admin.registration.catalog.controller.PermissionManifestController;
import top.egon.cola.platform.tianquan.jianshen.admin.registration.catalog.controller.PermissionCatalogActivationController;
import top.egon.cola.platform.tianquan.jianshen.contract.permission.ManifestRegistrationRequest;
import top.egon.cola.platform.tianquan.jianshen.contract.permission.PermissionManifestCanonicalizer;
import top.egon.cola.platform.tianquan.jianshen.core.registration.PermissionManifestDiff;
import top.egon.cola.platform.tianquan.jianshen.core.rule.Rbac3RuleViolation;
import top.egon.cola.platform.tianquan.shoubing.contract.ServiceIdentityPrincipal;
import top.egon.cola.platform.tianquan.shoubing.contract.ServiceTokenContext;
import top.egon.cola.platform.tianquan.shoubing.starter.security.AccessTokenVerification;
import top.egon.cola.platform.tianquan.shoubing.starter.security.IdpBearerAuthenticationFilter;
import top.egon.cola.platform.tianquan.shoubing.starter.security.IdpEndpointAuthenticationPolicy;
import top.egon.cola.platform.tianquan.shoubing.starter.security.IdpObservedVerificationComponent;
import top.egon.cola.platform.tianquan.shoubing.starter.security.IdpSecurityObservationFilter;
import top.egon.cola.platform.tianquan.shoubing.starter.security.ServiceAccessTokenVerifier;
import top.egon.cola.platform.tianquan.shoubing.starter.security.ServiceScopeAuthorization;
import top.egon.cola.platform.tianquan.shoubing.starter.security.UserAccessTokenVerifier;
import top.egon.cola.platform.tianquan.shoubing.starter.security.domain.TokenAuditProofBO;

import java.util.List;
import java.util.Set;

import static org.junit.jupiter.api.Assertions.assertNull;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.anyString;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.doAnswer;
import static org.mockito.Mockito.verifyNoInteractions;
import static org.mockito.Mockito.when;
import static org.springframework.security.test.web.servlet.setup.SecurityMockMvcConfigurers.springSecurity;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.post;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.header;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.jsonPath;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

/** Real MVC/Security filters with explicit verifier and domain doubles; no port or database is opened. */
class PermissionManifestSecurityTest {

    private AnnotationConfigWebApplicationContext context;
    private MockMvc mvc;
    private ServiceAccessTokenVerifier services;
    private UserAccessTokenVerifier users;
    private PermissionManifestPlanService plans;
    private PermissionCatalogJson json;

    @BeforeEach
    void prepare() {
        context = new AnnotationConfigWebApplicationContext();
        context.setServletContext(new MockServletContext());
        context.register(FixtureConfiguration.class);
        context.refresh();
        mvc = MockMvcBuilders.webAppContextSetup(context).apply(springSecurity()).build();
        services = context.getBean(ServiceAccessTokenVerifier.class);
        users = context.getBean(UserAccessTokenVerifier.class);
        plans = context.getBean(PermissionManifestPlanService.class);
        json = context.getBean(PermissionCatalogJson.class);
        when(services.verify("valid")).thenReturn(valid(PermissionCatalogFixture.caller().principal(), true));
        when(users.verify("valid")).thenReturn(new AccessTokenVerification.Invalid<>("JWT_PRINCIPAL_TYPE_INVALID"));
        var manifest = PermissionCatalogFixture.manifest();
        when(plans.plan(any(), any())).thenReturn(new PermissionManifestPlanService.Result("100", PermissionCatalogFixture.SCOPE,
                "api", "0", "0", new PermissionManifestCanonicalizer().digests(manifest),
                new PermissionManifestDiff().compare(null, manifest, Set.of()), PermissionCatalogFixture.NOW.plusSeconds(300)));
    }

    @AfterEach
    void close() {
        context.close();
        SecurityContextHolder.clearContext();
        org.slf4j.MDC.clear();
    }

    @Test
    void verifiedMachinePlanUsesNoUserRuntimeOrSession() throws Exception {
        var result = mvc.perform(post("/api/v1/permission-manifests/plans").header("Authorization", "Bearer valid")
                        .contentType(MediaType.APPLICATION_JSON).content(body()))
                .andExpect(status().isOk()).andExpect(jsonPath("$.data.planId").value("100")).andReturn();
        assertNull(result.getRequest().getSession(false));
        assertNull(SecurityContextHolder.getContext().getAuthentication());
        verifyNoInteractions(users);
    }

    @Test
    void absentBearerAndCookieOnlyRequestsCannotReachThePlanService() throws Exception {
        mvc.perform(post("/api/v1/permission-manifests/plans").contentType(MediaType.APPLICATION_JSON).content(body()))
                .andExpect(status().isUnauthorized()).andExpect(header().string("WWW-Authenticate", "Bearer"));
        var result = mvc.perform(post("/api/v1/permission-manifests/plans").cookie(new jakarta.servlet.http.Cookie("access", "valid"))
                        .contentType(MediaType.APPLICATION_JSON).content(body())).andExpect(status().isUnauthorized()).andReturn();
        assertNull(result.getRequest().getSession(false));
        verifyNoInteractions(plans, services, users);
    }

    @Test
    void userTokenIsNeverRetriedAsAUserPrincipal() throws Exception {
        when(services.verify("user")).thenReturn(new AccessTokenVerification.Invalid<>("SERVICE_PRINCIPAL_REQUIRED"));
        mvc.perform(post("/api/v1/permission-manifests/plans").header("Authorization", "Bearer user")
                .contentType(MediaType.APPLICATION_JSON).content(body())).andExpect(status().isUnauthorized());
        verifyNoInteractions(users, plans);
    }

    @Test
    void missingScopePlatformContextAndUnverifiedIssuerAreDenied() throws Exception {
        var original = PermissionCatalogFixture.caller().principal();
        var noScope = new ServiceIdentityPrincipal(original.subject(), original.tenantId(), original.clientId(), original.tokenId(),
                original.resourceUri(), original.resourceVersion(), Set.of("irrelevant"), original.sourceBizCode(), original.sourceAppCode(),
                original.sourceEnvironment(), original.credentialId(), original.issuedAt(), original.expiresAt(), original.appId(), original.scopeContext());
        var platform = new ServiceIdentityPrincipal(original.subject(), null, original.clientId(), original.tokenId(),
                original.resourceUri(), original.resourceVersion(), original.scopes(), original.sourceBizCode(), original.sourceAppCode(),
                original.sourceEnvironment(), original.credentialId(), original.issuedAt(), original.expiresAt(), original.appId(), ServiceTokenContext.PLATFORM);
        when(services.verify("scope")).thenReturn(valid(noScope, true));
        when(services.verify("platform")).thenReturn(valid(platform, true));
        when(services.verify("issuer")).thenReturn(valid(original, false));
        for (String token : List.of("scope", "platform", "issuer")) {
            mvc.perform(post("/api/v1/permission-manifests/plans").header("Authorization", "Bearer " + token)
                    .contentType(MediaType.APPLICATION_JSON).content(body())).andExpect(status().isForbidden());
        }
        verifyNoInteractions(plans);
    }

    @Test
    void authorityUnavailableAndMalformedEnvelopeNeverInvokeBusinessCode() throws Exception {
        when(services.verify("unavailable")).thenReturn(new AccessTokenVerification.Unavailable<>("IDENTITY_STATE_UNAVAILABLE"));
        mvc.perform(post("/api/v1/permission-manifests/plans").header("Authorization", "Bearer unavailable")
                .contentType(MediaType.APPLICATION_JSON).content(body())).andExpect(status().isServiceUnavailable());
        mvc.perform(post("/api/v1/permission-manifests/plans").header("Authorization", "Bearer valid")
                .contentType(MediaType.APPLICATION_JSON).content("{\"activate\":true}"))
                .andExpect(status().isUnprocessableEntity());
        verifyNoInteractions(plans);
    }

    @Test
    void grantDenialRequiresStrictAuditBeforeReturning403() throws Exception {
        var observations = context.getBean(IdpObservedVerificationComponent.class);
        when(observations.enabled()).thenReturn(true);
        when(observations.authorizationDenied(any(), anyString())).thenReturn(false);
        when(plans.plan(any(), any())).thenThrow(new Rbac3RuleViolation("SERVICE_IDENTITY_DENIED"));
        mvc.perform(post("/api/v1/permission-manifests/plans").header("Authorization", "Bearer valid")
                        .contentType(MediaType.APPLICATION_JSON).content(body()))
                .andExpect(status().isServiceUnavailable()).andExpect(jsonPath("$.status").value("OAUTH_AUDIT_DELIVERY_UNAVAILABLE"));
    }

    @Test
    void operationLookupRequiresTheFullTarget() throws Exception {
        mvc.perform(get("/api/v1/permission-manifests/registrations/" + PermissionCatalogFixture.OPERATION).header("Authorization", "Bearer valid"))
                .andExpect(status().isUnprocessableEntity());
        verifyNoInteractions(context.getBean(PermissionManifestRegistrationService.class));
    }

    @Test
    void registerCapabilityAndForgedDeploymentHeadersCannotActivateOrQualify() throws Exception {
        for (String path : List.of("/api/v1/permission-catalogs/activations", "/internal/v1/permission-catalogs/deployment-qualifications")) {
            mvc.perform(post(path).header("Authorization", "Bearer valid").header("X-Deployment-Verified", "true")
                    .contentType(MediaType.APPLICATION_JSON).content("{}"))
                    .andExpect(status().isForbidden());
        }
        verifyNoInteractions(context.getBean(PermissionCatalogActivationService.class), context.getBean(DeploymentQualificationService.class));
    }

    @Test
    void descriptorUsesServiceReadScopeAndRejectsPathTargetOrDuplicateQueryMismatch() throws Exception {
        catalogToken("tianquan-jianshen:permission-catalog:read");
        var query = new org.springframework.util.LinkedMultiValueMap<String, String>();
        ManifestRegistrationRequest.targetMap(PermissionCatalogFixture.SCOPE).forEach((key, value) -> query.add(key, value.toString()));
        query.add("producerId", "api");
        mvc.perform(get("/internal/v1/permission-catalogs/2/activations/1").queryParams(query)
                .header("Authorization", "Bearer catalog")).andExpect(status().isUnprocessableEntity());
        query.add("tenantId", "11");
        mvc.perform(get("/internal/v1/permission-catalogs/1/activations/1").queryParams(query)
                .header("Authorization", "Bearer catalog")).andExpect(status().isUnprocessableEntity());
        verifyNoInteractions(context.getBean(PermissionCatalogActivationService.class));
    }

    @Test
    void activationRejectsNumericVersionsBeforeCallingDomainService() throws Exception {
        catalogToken("tianquan-jianshen:permission-catalog:activate");
        String invalid = "{\"target\":" + json.write(PermissionCatalogFixture.SCOPE) + ",\"operationId\":\""
                + PermissionCatalogFixture.OPERATION + "\",\"expectedActiveRevision\":0,\"producers\":[{\"producerId\":\"api\",\"producerVersion\":\"1\",\"qualificationId\":\"301\"}]}";
        mvc.perform(post("/api/v1/permission-catalogs/activations").header("Authorization", "Bearer catalog")
                .contentType(MediaType.APPLICATION_JSON).content(invalid)).andExpect(status().isUnprocessableEntity());
        verifyNoInteractions(context.getBean(PermissionCatalogActivationService.class));
    }

    private void catalogToken(String scope) {
        var original = PermissionCatalogFixture.caller().principal();
        var token = new ServiceIdentityPrincipal(original.subject(), original.tenantId(), original.clientId(), original.tokenId(),
                original.resourceUri(), original.resourceVersion(), Set.of(scope), original.sourceBizCode(), original.sourceAppCode(),
                original.sourceEnvironment(), original.credentialId(), original.issuedAt(), original.expiresAt(), original.appId(), original.scopeContext());
        when(services.verify("catalog")).thenReturn(valid(token, true));
        when(users.verify("catalog")).thenReturn(new AccessTokenVerification.Invalid<>("JWT_PRINCIPAL_TYPE_INVALID"));
    }

    private String body() {
        return json.write(new ManifestRegistrationRequest.Plan(PermissionCatalogFixture.SCOPE, PermissionCatalogFixture.manifest(), "0", "0"));
    }

    private AccessTokenVerification.Valid<ServiceIdentityPrincipal> valid(ServiceIdentityPrincipal principal, boolean issuer) {
        var caller = PermissionCatalogFixture.caller();
        return new AccessTokenVerification.Valid<>(principal, principal.scopes(), new TokenAuditProofBO(caller.issuer(), principal.resourceUri(),
                "a".repeat(64), "b".repeat(64), "c".repeat(64)), issuer ? caller.issuer() : null);
    }

    @Configuration(proxyBeanMethods = false)
    @EnableWebMvc
    @EnableWebSecurity
    @EnableMethodSecurity
    @Import({PermissionCatalogSecurityConfiguration.class, PermissionManifestController.class, PermissionCatalogActivationController.class, PermissionCatalogExceptionHandler.class, PermissionCatalogJson.class})
    static class FixtureConfiguration {
        @Bean("jacksonObjectMapper") ObjectMapper mapper() { return new ObjectMapper().registerModule(new JavaTimeModule()); }
        @Bean PermissionManifestPlanService plans() { return mock(PermissionManifestPlanService.class); }
        @Bean PermissionCatalogActivationService activations() { return mock(PermissionCatalogActivationService.class); }
        @Bean DeploymentQualificationService qualifications() { return mock(DeploymentQualificationService.class); }
        @Bean PermissionManifestRegistrationService registrations() { return mock(PermissionManifestRegistrationService.class); }
        @Bean ServiceAccessTokenVerifier services() { return mock(ServiceAccessTokenVerifier.class); }
        @Bean UserAccessTokenVerifier users() { return mock(UserAccessTokenVerifier.class); }
        @Bean ServiceScopeAuthorization serviceScopeAuthorization() { return new ServiceScopeAuthorization(); }
        @Bean static AnnotationTemplateExpressionDefaults templateDefaults() { return new AnnotationTemplateExpressionDefaults(); }
        @Bean IdpObservedVerificationComponent observations() { return mock(IdpObservedVerificationComponent.class); }
        @Bean IdpEndpointAuthenticationPolicy policy() { return new IdpEndpointAuthenticationPolicy(List.of(), List.of("/api/v1/permission-manifests/**", "/internal/v1/permission-catalogs/**"),
                List.of("/api/v1/permission-catalogs/activations", "/api/v1/permission-catalogs/versions"), true); }
        @Bean("rbac3BearerAuthenticationFilter") top.egon.cola.platform.tianquan.jianshen.starter.security.Rbac3BearerAuthenticationFilter rbac() throws Exception {
            var filter = mock(top.egon.cola.platform.tianquan.jianshen.starter.security.Rbac3BearerAuthenticationFilter.class);
            doAnswer(invocation -> {
                ((jakarta.servlet.FilterChain) invocation.getArgument(2)).doFilter(invocation.getArgument(0), invocation.getArgument(1));
                return null;
            }).when(filter).doFilter(any(), any(), any());
            return filter;
        }
        @Bean("idpBearerAuthenticationFilter") IdpBearerAuthenticationFilter bearer(UserAccessTokenVerifier users, ServiceAccessTokenVerifier services,
                IdpEndpointAuthenticationPolicy policy, ObjectMapper mapper) { return new IdpBearerAuthenticationFilter(users, services, policy, mapper); }
        @Bean("idpSecurityObservationFilter") IdpSecurityObservationFilter observation(IdpObservedVerificationComponent observations,
                IdpEndpointAuthenticationPolicy policy) { return new IdpSecurityObservationFilter(observations, policy); }
    }
}
