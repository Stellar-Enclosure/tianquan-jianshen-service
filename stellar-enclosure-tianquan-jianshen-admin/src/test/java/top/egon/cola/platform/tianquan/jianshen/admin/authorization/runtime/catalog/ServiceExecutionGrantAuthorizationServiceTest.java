package top.egon.cola.platform.tianquan.jianshen.admin.authorization.runtime.catalog;

import java.net.URI;
import java.time.Clock;
import java.time.Instant;
import java.time.ZoneOffset;
import java.util.List;
import java.util.Map;
import java.util.Optional;
import java.util.Set;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.springframework.security.core.context.SecurityContextHolder;
import top.egon.cola.platform.tianquan.jianshen.contract.authorization.RuntimePolicyBinding;
import top.egon.cola.platform.tianquan.jianshen.contract.authorization.ServiceExecutionAuthorizationContract;
import top.egon.cola.platform.tianquan.jianshen.contract.authorization.ServicePolicySnapshot;
import top.egon.cola.platform.tianquan.jianshen.contract.permission.DefinitionLifecycle;
import top.egon.cola.platform.tianquan.jianshen.contract.permission.PermissionManifest;
import top.egon.cola.platform.tianquan.jianshen.contract.permission.ResourceAccess;
import top.egon.cola.platform.tianquan.jianshen.contract.permission.ResourceType;
import top.egon.cola.platform.tianquan.jianshen.core.rule.Rbac3RuleViolation;
import top.egon.cola.platform.tianquan.shoubing.contract.ServiceIdentityPrincipal;
import top.egon.cola.platform.tianquan.shoubing.contract.ServiceTokenContext;
import top.egon.cola.platform.tianquan.shoubing.contract.execution.ServiceExecutionGrantContract;
import top.egon.cola.platform.tianquan.shoubing.starter.execution.HttpExecutionGrantClient;
import top.egon.cola.platform.tianquan.shoubing.starter.security.IdpAuthenticationToken;
import top.egon.cola.platform.tianquan.shoubing.starter.security.TrustedIssuerRegistry;

import static org.junit.jupiter.api.Assertions.*;
import static org.mockito.ArgumentMatchers.*;
import static org.mockito.Mockito.*;
import static top.egon.cola.platform.tianquan.jianshen.admin.authorization.runtime.catalog.RuntimeProofBindingTest.*;

class ServiceExecutionGrantAuthorizationServiceTest {
    private static final String ID = "8" + "1".repeat(62);
    private static final String INTENT = "00000000-0000-0000-0000-000000000123";
    private static final String PURPOSE = "TIANJI_AGENT_RUN_EXECUTION";
    private static final String SUBMIT = "tianji:agent:linked:submit";
    private static final String SESSION = "tianji:agent:session";
    private static final String KEY = "tianji.api.agent.linked";
    private static final String SESSION_KEY = "tianji.api.agent.linkedSession";
    private final PermissionRuntimeProofService proofs = mock(PermissionRuntimeProofService.class);
    private final PermissionRuntimeSnapshotRepository snapshots = mock(PermissionRuntimeSnapshotRepository.class);
    private final TrustedIssuerRegistry issuers = mock(TrustedIssuerRegistry.class);
    private final HttpExecutionGrantClient client = mock(HttpExecutionGrantClient.class);
    private final ServiceIdentityPrincipal caller = new ServiceIdentityPrincipal("shop-runtime", "20", "shop-runtime", "45", RECEIVER,
            0, Set.of(ServiceExecutionAuthorizationContract.SERVICE_SCOPE), "commerce", "shop", "test", "credential",
            NOW.minusSeconds(10), NOW.plusSeconds(100), "shop-client", ServiceTokenContext.TENANT);
    private final ServiceExecutionGrantAuthorizationService.Request request = new ServiceExecutionGrantAuthorizationService.Request(
            "shop", new ServiceExecutionGrantContract.Ticket(ID, "ENC:v1:key:nonce:fixture"));
    private final TrustedIssuerRegistry.TrustedIssuerVO trust = new TrustedIssuerRegistry.TrustedIssuerVO(ISSUER,
            URI.create("https://idp.example/jwks"), "tenant:20", TrustedIssuerRegistry.RealmType.TENANT, "20",
            TrustedIssuerRegistry.Status.ACTIVE, 3);
    private ServiceExecutionGrantAuthorizationService service;

    @BeforeEach void setUp() {
        SecurityContextHolder.getContext().setAuthentication(new IdpAuthenticationToken(caller, List.of(), ISSUER));
        when(issuers.findByIssuer(ISSUER.toASCIIString())).thenReturn(Optional.of(trust));
        when(proofs.policyBinding(caller, ISSUER, "shop", ServiceExecutionAuthorizationContract.SERVICE_SCOPE)).thenReturn(binding());
        when(client.resolveService(any())).thenReturn(grant(true, Set.of(SUBMIT, SESSION)));
        when(snapshots.currentServiceExecution(any(), any(), anyString())).thenAnswer(inv -> {
            String key = inv.getArgument(2);
            return view(key, key.equals(SESSION_KEY), NOW.plusSeconds(30));
        });
        service = new ServiceExecutionGrantAuthorizationService(proofs, snapshots, issuers,
                Map.of(new ExecutionGrantAuthorizationService.AuthorityKey(ISSUER, RESOURCE), client), policies(), Clock.fixed(NOW, ZoneOffset.UTC));
    }

    @AfterEach void clear() { SecurityContextHolder.clearContext(); }

    @Test void verifies_the_attested_service_without_creating_a_user_principal_or_snapshot() {
        var decision = service.decide(caller, ISSUER, request);
        assertEquals(ID, decision.grantId());
        assertEquals("worker", decision.subject());
        assertEquals("20", decision.tenantId());
        assertEquals(INTENT, decision.intentId());
        assertEquals("c".repeat(64), decision.bindingSha256());
        assertEquals("https://api.example/process", decision.subjectSource().resourceUri());
        assertTrue(decision.sessionRequired());
        assertEquals(NOW.plusSeconds(30), decision.expiresAt());
        assertEquals(1, decision.catalogVersion());
        assertEquals(3, decision.policyVersion());
        verify(snapshots).currentServiceExecution(binding(), NOW.plusSeconds(60), SESSION_KEY);
        verify(snapshots, never()).currentExecution(any());
        assertFalse(decision.toString().contains("worker"));
    }

    @Test void transport_adapter_returns_the_exact_service_tuple_and_versions() {
        var body = new ServiceExecutionAuthorizationContract.Request("shop", ID, "ENC:v1:key:nonce:fixture");
        var decision = service.decide(caller, ISSUER, body);
        assertEquals("worker", decision.subject());
        assertEquals("worker", decision.subjectSource().clientId());
        assertEquals("https://api.example/process", decision.subjectSource().resourceUri());
        assertEquals(INTENT, decision.intentId());
        assertEquals(1, decision.catalogVersion());
        assertEquals(3, decision.policyVersion());
        assertFalse(decision.toString().contains("worker"));
    }

    @Test void rejects_unverified_callers_and_missing_issuer_before_resolving_a_ticket() {
        SecurityContextHolder.clearContext();
        assertDenied(() -> service.decide(caller, ISSUER, request));
        SecurityContextHolder.getContext().setAuthentication(new IdpAuthenticationToken(caller));
        assertDenied(() -> service.decide(caller, ISSUER, request));
        SecurityContextHolder.getContext().setAuthentication(new IdpAuthenticationToken(caller, List.of(), URI.create("https://other.example/20")));
        assertDenied(() -> service.decide(caller, ISSUER, request));
        verifyNoInteractions(client, snapshots);
    }

    @Test void source_tenant_issuer_and_subject_tuple_must_match() {
        var original = grant(false, Set.of(SUBMIT));
        var source = original.source();
        var worker = original.subjectSource();
        for (var wrong : List.of(
                copy(original, "https://other.example/tenants/20", 20, source, worker, original.purpose()),
                copy(original, ISSUER.toString(), 21, source, worker, original.purpose()),
                copy(original, ISSUER.toString(), 20, new ServiceExecutionGrantContract.Source("other", source.appId(),
                        source.businessCode(), source.applicationCode(), source.environment(), source.resourceUri()), worker, original.purpose()),
                copy(original, ISSUER.toString(), 20, new ServiceExecutionGrantContract.Source(source.clientId(), source.appId(),
                        source.businessCode(), source.applicationCode(), source.environment(), "https://foreign.example/shop"), worker, original.purpose()),
                copy(original, ISSUER.toString(), 20, source, new ServiceExecutionGrantContract.Source(worker.clientId(), worker.appId(),
                        worker.businessCode(), worker.applicationCode(), "prod", worker.resourceUri()), original.purpose()),
                copy(original, ISSUER.toString(), 20, source, new ServiceExecutionGrantContract.Source(worker.clientId(), "other-app",
                        worker.businessCode(), worker.applicationCode(), worker.environment(), worker.resourceUri()), original.purpose()),
                copy(original, ISSUER.toString(), 20, source, new ServiceExecutionGrantContract.Source(worker.clientId(), worker.appId(),
                        worker.businessCode(), worker.applicationCode(), worker.environment(), "https://foreign.example/process"), original.purpose()))) {
            when(client.resolveService(any())).thenReturn(wrong);
            assertDenied(() -> service.decide(caller, ISSUER, request));
        }
        when(client.resolveService(any())).thenReturn(copy(original, ISSUER.toString(), 20, source, worker, "OTHER_PURPOSE"));
        assertUnavailable(() -> service.decide(caller, ISSUER, request));
        verifyNoInteractions(snapshots);
    }

    @Test void configured_scope_and_active_resource_scope_are_both_required() {
        when(client.resolveService(any())).thenReturn(grant(true, Set.of(SUBMIT)));
        assertDenied(() -> service.decide(caller, ISSUER, request));
        verifyNoInteractions(snapshots);
        when(client.resolveService(any())).thenReturn(grant(false, Set.of(SUBMIT)));
        var base = view(KEY, false, NOW.plusSeconds(30));
        var changed = new PermissionManifest.ResourceDefinition(KEY, ResourceType.API, base.resource().target(),
                ResourceAccess.PROTECTED, null, null, List.of(PermissionManifest.PrincipalType.SERVICE), List.of(SUBMIT, "agent:new"),
                base.resource().i18n(), DefinitionLifecycle.ACTIVE);
        doReturn(new PermissionRuntimeSnapshotRepository.ServiceExecutionView(base.snapshot(), changed))
                .when(snapshots).currentServiceExecution(any(), any(), anyString());
        assertDenied(() -> service.decide(caller, ISSUER, request));
    }

    @Test void changed_deployment_resource_or_nonservice_policy_never_allows_execution() {
        var expected = view(SESSION_KEY, true, NOW.plusSeconds(30));
        var wrongPath = new PermissionManifest.ResourceDefinition(SESSION_KEY, ResourceType.API,
                Map.of("methods", List.of("POST"), "paths", List.of("/api/tianji/v1/other")), ResourceAccess.PROTECTED,
                null, null, List.of(PermissionManifest.PrincipalType.SERVICE), List.of(SUBMIT, SESSION),
                expected.resource().i18n(), DefinitionLifecycle.ACTIVE);
        doReturn(new PermissionRuntimeSnapshotRepository.ServiceExecutionView(expected.snapshot(), wrongPath))
                .when(snapshots).currentServiceExecution(any(), any(), anyString());
        assertUnavailable(() -> service.decide(caller, ISSUER, request));
        var wrongPrincipal = new PermissionManifest.ResourceDefinition(SESSION_KEY, ResourceType.API, expected.resource().target(),
                ResourceAccess.PROTECTED, new top.egon.cola.platform.tianquan.jianshen.contract.permission.PermissionRequirement(
                top.egon.cola.platform.tianquan.jianshen.contract.permission.PermissionMode.ALL, List.of("X")), null,
                List.of(PermissionManifest.PrincipalType.USER), List.of(SUBMIT), expected.resource().i18n(), DefinitionLifecycle.ACTIVE);
        doReturn(new PermissionRuntimeSnapshotRepository.ServiceExecutionView(expected.snapshot(), wrongPrincipal))
                .when(snapshots).currentServiceExecution(any(), any(), anyString());
        assertUnavailable(() -> service.decide(caller, ISSUER, request));
        doReturn(view(SESSION_KEY, true, NOW.plusSeconds(61))).when(snapshots).currentServiceExecution(any(), any(), anyString());
        assertUnavailable(() -> service.decide(caller, ISSUER, request));
        var snapshot = new ServicePolicySnapshot(SCOPE, "1", "3", new RuntimePolicyBinding("shop-java", "1",
                "f".repeat(64), "b".repeat(64), "c".repeat(64)), Set.of(SESSION_KEY), NOW.plusSeconds(30));
        doReturn(new PermissionRuntimeSnapshotRepository.ServiceExecutionView(snapshot, expected.resource()))
                .when(snapshots).currentServiceExecution(any(), any(), anyString());
        assertUnavailable(() -> service.decide(caller, ISSUER, request));
        var missingResource = new ServicePolicySnapshot(SCOPE, "1", "3", expected.snapshot().policyBinding(), Set.of(), NOW.plusSeconds(30));
        doReturn(new PermissionRuntimeSnapshotRepository.ServiceExecutionView(missingResource, expected.resource()))
                .when(snapshots).currentServiceExecution(any(), any(), anyString());
        assertUnavailable(() -> service.decide(caller, ISSUER, request));
        doReturn(view(SESSION_KEY, true, NOW)).when(snapshots).currentServiceExecution(any(), any(), anyString());
        assertDenied(() -> service.decide(caller, ISSUER, request));
    }

    @Test void owner_denial_dependency_failure_and_trust_changes_remain_distinct() {
        doThrow(new HttpExecutionGrantClient.ExecutionGrantDeniedException()).when(client).resolveService(any());
        assertDenied(() -> service.decide(caller, ISSUER, request));
        doThrow(new HttpExecutionGrantClient.ExecutionGrantUnavailableException()).when(client).resolveService(any());
        assertUnavailable(() -> service.decide(caller, ISSUER, request));
        doReturn(grant(true, Set.of(SUBMIT, SESSION))).when(client).resolveService(any());
        doThrow(new Rbac3RuleViolation("APPLICATION_BINDING_DENIED")).when(snapshots).currentServiceExecution(any(), any(), anyString());
        assertDenied(() -> service.decide(caller, ISSUER, request));
        doThrow(new Rbac3RuleViolation("AUTH_DEPLOYMENT_BINDING_MISMATCH")).when(snapshots).currentServiceExecution(any(), any(), anyString());
        assertUnavailable(() -> service.decide(caller, ISSUER, request));
        doReturn(view(SESSION_KEY, true, NOW.plusSeconds(30))).when(snapshots).currentServiceExecution(any(), any(), anyString());
        when(issuers.findByIssuer(ISSUER.toString())).thenReturn(Optional.of(trust), Optional.empty());
        assertUnavailable(() -> service.decide(caller, ISSUER, request));
    }

    @Test void deployment_policies_require_exact_tenant_subject_and_finite_scopes() {
        assertThrows(IllegalArgumentException.class, () -> new ServiceExecutionGrantAuthorizationProperties(true, List.of()));
        var policy = policies().policies().getFirst();
        assertThrows(IllegalArgumentException.class, () -> new ServiceExecutionGrantAuthorizationProperties(true, List.of(policy, policy)));
        assertThrows(IllegalArgumentException.class, () -> new ServiceExecutionGrantAuthorizationProperties.Policy(
                ISSUER.toString(), "20", "shop", PURPOSE, KEY, "/api/../admin", null, null, Set.of(SUBMIT), Set.of(), policy.subjects()));
        assertThrows(IllegalArgumentException.class, () -> new ServiceExecutionGrantAuthorizationProperties.Policy(
                ISSUER.toString(), "20", "shop", PURPOSE, KEY, "/api/tianji/linked", SESSION_KEY, null,
                Set.of(SUBMIT), Set.of(SESSION), policy.subjects()));
        assertThrows(IllegalArgumentException.class, () -> new ServiceExecutionGrantAuthorizationProperties.Policy(
                ISSUER.toString(), "20", "shop", PURPOSE, KEY, "/api/tianji/linked", null, null, Set.of(SUBMIT), Set.of(), List.of()));
        assertThrows(IllegalArgumentException.class, () -> new ServiceExecutionGrantAuthorizationProperties.Subject(
                "worker", "process", "platform", "process", "test", "http://api.example/process"));
    }

    @Test void configured_owner_binding_is_loaded_without_acquiring_tokens_at_startup() {
        new org.springframework.boot.test.context.runner.ApplicationContextRunner()
                .withUserConfiguration(ServiceExecutionGrantAuthorizationService.class)
                .run(context -> assertTrue(context.getBeansOfType(ServiceExecutionGrantAuthorizationService.class).isEmpty()));
        var authority = new top.egon.cola.platform.tianquan.shoubing.starter.state.IdentityAuthorityProperties();
        authority.setBaseUri(URI.create("https://idp.example"));
        var configured = new top.egon.cola.platform.tianquan.shoubing.starter.state.IdentityAuthorityProperties.Binding();
        configured.setIssuer(ISSUER); configured.setSourceResource(RESOURCE); configured.setRegistrationId("registration");
        configured.setAudience(URI.create("https://idp.example/resource")); configured.setContext(ServiceTokenContext.TENANT);
        configured.setTenantId("20"); configured.setScopes(Set.of(
                top.egon.cola.platform.tianquan.shoubing.contract.state.IdentityAuthorityScopes.SERVICE_EXECUTION_GRANT_RESOLVE));
        authority.setBindings(Map.of("shop", configured));
        var starter = new top.egon.cola.platform.tianquan.shoubing.starter.autoconfigure.IdpStarterProperties();
        starter.setResourceUri(RESOURCE); starter.getServiceClient().setAppId("rbac-app");
        var oauth = mock(top.egon.cola.platform.tianquan.shoubing.starter.client.IdpServiceOAuth2Client.class);
        when(oauth.authorizationKey(any())).thenAnswer(inv -> {
            top.egon.cola.platform.tianquan.shoubing.starter.client.IdpServiceTokenRequest value = inv.getArgument(0);
            return new top.egon.cola.platform.tianquan.shoubing.starter.client.ServiceAuthorizationKey(ISSUER.toString(),
                    value.registrationId(), "rbac", 1, value.appId(), value.audience(), value.context(), value.tenantId(), value.scopes());
        });
        String p = "egon.tianquan-jianshen.service-execution-grants.";
        String b = p + "policies[0].";
        new org.springframework.boot.test.context.runner.ApplicationContextRunner().withUserConfiguration(EnabledConfiguration.class)
                .withPropertyValues(p + "enabled=true", b + "issuer=" + ISSUER, b + "tenant-id=20", b + "system-code=shop",
                        b + "purpose=" + PURPOSE, b + "resource-key=" + KEY, b + "resource-path=/api/tianji/linked",
                        b + "session-resource-key=" + SESSION_KEY, b + "session-resource-path=/api/tianji/linked-session",
                        b + "required-scopes[0]=" + SUBMIT, b + "session-scopes[0]=" + SESSION,
                        b + "subjects[0].client-id=worker", b + "subjects[0].app-id=process",
                        b + "subjects[0].business-code=platform", b + "subjects[0].application-code=process",
                        b + "subjects[0].environment=test", b + "subjects[0].resource-uri=https://api.example/process")
                .withBean(PermissionRuntimeProofService.class, () -> proofs)
                .withBean(PermissionRuntimeSnapshotRepository.class, () -> snapshots)
                .withBean("identityAuthorityProperties", top.egon.cola.platform.tianquan.shoubing.starter.state.IdentityAuthorityProperties.class, () -> authority)
                .withBean("idpStarterProperties", top.egon.cola.platform.tianquan.shoubing.starter.autoconfigure.IdpStarterProperties.class, () -> starter)
                .withBean("trustedIssuerRegistry", TrustedIssuerRegistry.class, () -> issuers)
                .withBean("idpServiceOAuth2Client", top.egon.cola.platform.tianquan.shoubing.starter.client.IdpServiceOAuth2Client.class, () -> oauth)
                .withBean("jacksonObjectMapper", com.fasterxml.jackson.databind.ObjectMapper.class, com.fasterxml.jackson.databind.ObjectMapper::new)
                .withBean("idpClock", Clock.class, () -> Clock.fixed(NOW, ZoneOffset.UTC))
                .run(context -> {
                    assertNull(context.getStartupFailure());
                    assertEquals(1, context.getBeansOfType(ServiceExecutionGrantAuthorizationService.class).size());
                    assertEquals(policies().policies().getFirst(), context.getBean(ServiceExecutionGrantAuthorizationProperties.class).policies().getFirst());
                });
        verify(oauth, never()).authorize(any());
        verify(oauth, never()).authorizeBounded(any(), anyString(), any());
        configured.setTenantId("21");
        assertThrows(IllegalStateException.class, () -> new ServiceExecutionGrantAuthorizationService(proofs, snapshots, policies(),
                authority, starter, issuers, oauth, new com.fasterxml.jackson.databind.ObjectMapper(), Clock.fixed(NOW, ZoneOffset.UTC)));
    }

    @org.springframework.context.annotation.Configuration(proxyBeanMethods = false)
    @org.springframework.boot.context.properties.EnableConfigurationProperties(ServiceExecutionGrantAuthorizationProperties.class)
    @org.springframework.context.annotation.Import(ServiceExecutionGrantAuthorizationService.class)
    static class EnabledConfiguration { }

    private static ServiceExecutionGrantAuthorizationProperties policies() {
        var subject = new ServiceExecutionGrantAuthorizationProperties.Subject("worker", "process", "platform", "process",
                "test", "https://api.example/process");
        return new ServiceExecutionGrantAuthorizationProperties(true, List.of(new ServiceExecutionGrantAuthorizationProperties.Policy(
                ISSUER.toASCIIString(), "20", "shop", PURPOSE, KEY, "/api/tianji/linked", SESSION_KEY,
                "/api/tianji/linked-session", Set.of(SUBMIT), Set.of(SESSION), List.of(subject))));
    }

    private static ServiceExecutionGrantContract.Resolution grant(boolean session, Set<String> scopes) {
        var source = new ServiceExecutionGrantContract.Source("shop-runtime", "shop-client", "commerce", "shop", "test", RESOURCE.toASCIIString());
        var subject = new ServiceExecutionGrantContract.Source("worker", "process", "platform", "process", "test", "https://api.example/process");
        return new ServiceExecutionGrantContract.Resolution(ID, ISSUER.toASCIIString(), 20, "worker", RESOURCE.toASCIIString(),
                source, subject, PURPOSE, INTENT, "c".repeat(64), session, NOW.plusSeconds(60), NOW.plusSeconds(600), scopes);
    }

    private static ServiceExecutionGrantContract.Resolution copy(ServiceExecutionGrantContract.Resolution value, String issuer, long tenant,
            ServiceExecutionGrantContract.Source source, ServiceExecutionGrantContract.Source subject, String purpose) {
        return new ServiceExecutionGrantContract.Resolution(value.grantId(), issuer, tenant, subject.clientId(), source.resourceUri(),
                source, subject, purpose, value.intentId(), value.bindingSha256(), value.sessionRequired(),
                value.expiresAt(), value.intentDeadlineAt(), value.scopes());
    }

    private static PermissionRuntimeSnapshotRepository.ServiceExecutionView view(String key, boolean session, Instant expiry) {
        var snapshot = new ServicePolicySnapshot(SCOPE, "1", "3", new RuntimePolicyBinding("shop-java", "1",
                "a".repeat(64), "b".repeat(64), "c".repeat(64)), Set.of(key), expiry);
        var resource = new PermissionManifest.ResourceDefinition(key, ResourceType.API,
                Map.of("methods", List.of("POST"), "paths", List.of(session ? "/api/tianji/linked-session" : "/api/tianji/linked")),
                ResourceAccess.PROTECTED, null, null, List.of(PermissionManifest.PrincipalType.SERVICE),
                session ? List.of(SUBMIT, SESSION) : List.of(SUBMIT), new PermissionManifest.I18nReference("tianji", "start"),
                DefinitionLifecycle.ACTIVE);
        return new PermissionRuntimeSnapshotRepository.ServiceExecutionView(snapshot, resource);
    }

    private static void assertDenied(Runnable action) {
        assertEquals("EXECUTION_GRANT_DENIED", assertThrows(Rbac3RuleViolation.class, action::run).reasonCode());
    }
    private static void assertUnavailable(Runnable action) {
        assertEquals("AUTH_RUNTIME_EXECUTION_UNAVAILABLE", assertThrows(Rbac3RuleViolation.class, action::run).reasonCode());
    }
}
