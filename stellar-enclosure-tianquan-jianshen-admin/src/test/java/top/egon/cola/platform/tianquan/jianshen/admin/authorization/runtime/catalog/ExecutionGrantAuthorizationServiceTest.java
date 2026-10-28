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
import top.egon.cola.platform.tianquan.jianshen.contract.authorization.ExecutionAuthorizationContract;
import top.egon.cola.platform.tianquan.jianshen.contract.authorization.RuntimePolicyBinding;
import top.egon.cola.platform.tianquan.jianshen.contract.authorization.SystemAuthorizationSnapshot;
import top.egon.cola.platform.tianquan.jianshen.contract.permission.DefinitionLifecycle;
import top.egon.cola.platform.tianquan.jianshen.contract.permission.EffectivePermissionSnapshot;
import top.egon.cola.platform.tianquan.jianshen.contract.permission.PermissionManifest;
import top.egon.cola.platform.tianquan.jianshen.contract.permission.PermissionMode;
import top.egon.cola.platform.tianquan.jianshen.contract.permission.PermissionRequirement;
import top.egon.cola.platform.tianquan.jianshen.contract.permission.ResourceAccess;
import top.egon.cola.platform.tianquan.jianshen.contract.permission.ResourceType;
import top.egon.cola.platform.tianquan.jianshen.core.rule.Rbac3RuleViolation;
import top.egon.cola.platform.tianquan.shoubing.contract.ServiceIdentityPrincipal;
import top.egon.cola.platform.tianquan.shoubing.contract.ServiceTokenContext;
import top.egon.cola.platform.tianquan.shoubing.contract.execution.ExecutionGrantContract;
import top.egon.cola.platform.tianquan.shoubing.starter.execution.HttpExecutionGrantClient;
import top.egon.cola.platform.tianquan.shoubing.starter.security.IdpAuthenticationToken;
import top.egon.cola.platform.tianquan.shoubing.starter.security.TrustedIssuerRegistry;

import static org.junit.jupiter.api.Assertions.*;
import static org.mockito.ArgumentMatchers.*;
import static org.mockito.Mockito.*;
import static top.egon.cola.platform.tianquan.jianshen.admin.authorization.runtime.catalog.RuntimeProofBindingTest.*;

class ExecutionGrantAuthorizationServiceTest {
    private static final String ID = "9" + "1".repeat(62);
    private static final String INTENT = "00000000-0000-0000-0000-000000000123";
    private static final String PURPOSE = "TIANJI_AGENT_RUN_EXECUTION";
    private static final String START = "TIANJI_AGENT_START";
    private static final String READ = "TIANJI_AGENT_READ";
    private final PermissionRuntimeProofService proofs = mock(PermissionRuntimeProofService.class);
    private final PermissionRuntimeSnapshotRepository snapshots = mock(PermissionRuntimeSnapshotRepository.class);
    private final TrustedIssuerRegistry issuers = mock(TrustedIssuerRegistry.class);
    private final HttpExecutionGrantClient client = mock(HttpExecutionGrantClient.class);
    private final ServiceIdentityPrincipal caller = new ServiceIdentityPrincipal("shop-runtime", "20", "shop-runtime", "45", RECEIVER,
            0, Set.of(ExecutionAuthorizationContract.SERVICE_SCOPE), "commerce", "shop", "test", "credential",
            NOW.minusSeconds(10), NOW.plusSeconds(100), "shop-client", ServiceTokenContext.TENANT);
    private final ExecutionAuthorizationContract.Request request = new ExecutionAuthorizationContract.Request("shop", ID, "ENC:v1:key:nonce:fixture");
    private final TrustedIssuerRegistry.TrustedIssuerVO trust = new TrustedIssuerRegistry.TrustedIssuerVO(ISSUER,
            URI.create("https://idp.example/jwks"), "tenant:20", TrustedIssuerRegistry.RealmType.TENANT, "20",
            TrustedIssuerRegistry.Status.ACTIVE, 3);
    private ExecutionGrantAuthorizationService service;

    @BeforeEach void setup() {
        SecurityContextHolder.getContext().setAuthentication(new IdpAuthenticationToken(caller, List.of(), ISSUER));
        when(issuers.findByIssuer(ISSUER.toString())).thenReturn(Optional.of(trust));
        when(proofs.policyBinding(caller, ISSUER, "shop", ExecutionAuthorizationContract.SERVICE_SCOPE)).thenReturn(binding());
        when(client.resolve(any())).thenReturn(grant(true, Set.of("tianji:agent:start", "tianji:agent:read")));
        when(snapshots.currentExecution(any())).thenAnswer(inv -> {
            ExecutionGrantAuthorizationService.VerifiedExecution verified = inv.getArgument(0);
            return view(verified.resourceKey(), Set.of(START, READ), true, NOW.plusSeconds(30));
        });
        service = new ExecutionGrantAuthorizationService(proofs, snapshots, issuers,
                Map.of(new ExecutionGrantAuthorizationService.AuthorityKey(ISSUER, RESOURCE), client), policies(), Clock.fixed(NOW, ZoneOffset.UTC));
    }

    @AfterEach void clear() { SecurityContextHolder.clearContext(); }

    @Test void verifies_source_and_current_roles_against_the_activated_resource() {
        var decision = service.decide(caller, ISSUER, request);
        assertEquals(ID, decision.grantId()); assertEquals("30", decision.subject());
        assertEquals("20", decision.tenantId()); assertEquals(INTENT, decision.intentId());
        assertEquals("c".repeat(64), decision.bindingSha256()); assertTrue(decision.sessionRequired());
        assertEquals(NOW.plusSeconds(30), decision.expiresAt()); assertEquals(2, decision.authVersion());
        assertEquals(3, decision.policyVersion());
        var captured = org.mockito.ArgumentCaptor.forClass(ExecutionGrantAuthorizationService.VerifiedExecution.class);
        verify(snapshots).currentExecution(captured.capture());
        assertEquals(binding(), captured.getValue().binding()); assertEquals("30", captured.getValue().subject());
        assertEquals("tianji.api.agent.startSession", captured.getValue().resourceKey());
        assertEquals(NOW.plusSeconds(60), captured.getValue().expiresAt());
    }

    @Test void session_access_requires_both_current_permission_and_scope() {
        when(client.resolve(any())).thenReturn(grant(true, Set.of("tianji:agent:start")));
        assertDenied(() -> service.decide(caller, ISSUER, request)); verifyNoInteractions(snapshots);
        when(client.resolve(any())).thenReturn(grant(true, Set.of("tianji:agent:start", "tianji:agent:read")));
        doReturn(view("tianji.api.agent.startSession", Set.of(START), true, NOW.plusSeconds(30))).when(snapshots).currentExecution(any());
        assertDenied(() -> service.decide(caller, ISSUER, request));
    }

    @Test void source_tenant_issuer_resource_and_purpose_must_all_match() {
        var original = grant(false, Set.of("tianji:agent:start"));
        for (var wrong : List.of(
                copy(original, "https://different.example/tenants/20", 20, RESOURCE.toString(), original.source(), original.purpose()),
                copy(original, ISSUER.toString(), 21, RESOURCE.toString(), original.source(), original.purpose()),
                copy(original, ISSUER.toString(), 20, "https://foreign.example/shop", original.source(), original.purpose()),
                copy(original, ISSUER.toString(), 20, RESOURCE.toString(), new ExecutionGrantContract.Source("other", "shop-client", "commerce", "shop", "test"), original.purpose()),
                copy(original, ISSUER.toString(), 20, RESOURCE.toString(), new ExecutionGrantContract.Source("shop-runtime", "shop-client", "commerce", "shop", "prod"), original.purpose()))) {
            when(client.resolve(any())).thenReturn(wrong); assertDenied(() -> service.decide(caller, ISSUER, request));
        }
        when(client.resolve(any())).thenReturn(copy(original, ISSUER.toString(), 20, RESOURCE.toString(), original.source(), "OTHER_PURPOSE"));
        assertUnavailable(() -> service.decide(caller, ISSUER, request));
        verifyNoInteractions(snapshots);
    }

    @Test void unverified_caller_or_missing_binding_never_reaches_the_owner() {
        SecurityContextHolder.clearContext();
        assertDenied(() -> service.decide(caller, ISSUER, request));
        SecurityContextHolder.getContext().setAuthentication(new IdpAuthenticationToken(caller, List.of(), URI.create("https://other.example/20")));
        assertDenied(() -> service.decide(caller, ISSUER, request));
        SecurityContextHolder.getContext().setAuthentication(new IdpAuthenticationToken(caller, List.of(), ISSUER));
        var noBinding = new ExecutionGrantAuthorizationService(proofs, snapshots, issuers,
                Map.of(new ExecutionGrantAuthorizationService.AuthorityKey(ISSUER, RECEIVER), client), policies(), Clock.fixed(NOW, ZoneOffset.UTC));
        assertUnavailable(() -> noBinding.decide(caller, ISSUER, request)); verifyNoInteractions(client, snapshots);
    }

    @Test void changed_active_policy_or_unmapped_permissions_never_allow_execution() {
        var expected = view("tianji.api.agent.startSession", Set.of(START, READ), true, NOW.plusSeconds(30));
        var changed = new PermissionManifest.ResourceDefinition(expected.resource().key(), ResourceType.API,
                Map.of("methods", List.of("POST"), "paths", List.of("/api/tianji/v1/other")), ResourceAccess.PROTECTED,
                expected.resource().requirement(), null, expected.resource().allowedPrincipals(), expected.resource().oauthScopes(),
                expected.resource().i18n(), DefinitionLifecycle.ACTIVE);
        doReturn(new PermissionRuntimeSnapshotRepository.ExecutionView(expected.snapshot(), changed)).when(snapshots).currentExecution(any());
        assertUnavailable(() -> service.decide(caller, ISSUER, request));
        var extra = new PermissionManifest.ResourceDefinition(expected.resource().key(), ResourceType.API, expected.resource().target(),
                ResourceAccess.PROTECTED, new PermissionRequirement(PermissionMode.ALL, List.of(START, READ, "NEW_PERMISSION")), null,
                expected.resource().allowedPrincipals(), expected.resource().oauthScopes(), expected.resource().i18n(), DefinitionLifecycle.ACTIVE);
        doReturn(new PermissionRuntimeSnapshotRepository.ExecutionView(expected.snapshot(), extra)).when(snapshots).currentExecution(any());
        assertDenied(() -> service.decide(caller, ISSUER, request));
        doReturn(view("tianji.api.agent.startSession", Set.of(START, READ), true, NOW.plusSeconds(61))).when(snapshots).currentExecution(any());
        assertUnavailable(() -> service.decide(caller, ISSUER, request));
    }

    @Test void definitive_denial_is_distinct_from_dependency_and_policy_unavailability() {
        doThrow(new HttpExecutionGrantClient.ExecutionGrantDeniedException()).when(client).resolve(any());
        assertDenied(() -> service.decide(caller, ISSUER, request));
        doThrow(new HttpExecutionGrantClient.ExecutionGrantUnavailableException()).when(client).resolve(any());
        assertUnavailable(() -> service.decide(caller, ISSUER, request));
        doReturn(grant(true, Set.of("tianji:agent:start", "tianji:agent:read"))).when(client).resolve(any());
        doThrow(new Rbac3RuleViolation("IDENTITY_INACTIVE")).when(snapshots).currentExecution(any());
        assertDenied(() -> service.decide(caller, ISSUER, request));
        doThrow(new Rbac3RuleViolation("AUTH_DEPLOYMENT_BINDING_MISMATCH")).when(snapshots).currentExecution(any());
        assertUnavailable(() -> service.decide(caller, ISSUER, request));
    }

    @Test void issuer_trust_change_during_decision_never_returns_allow() {
        when(issuers.findByIssuer(ISSUER.toString())).thenReturn(Optional.of(trust), Optional.empty());
        assertUnavailable(() -> service.decide(caller, ISSUER, request));
    }

    @Test void enabled_policies_require_unique_purposes_paths_and_scope_mappings() {
        assertThrows(IllegalArgumentException.class, () -> new ExecutionGrantAuthorizationProperties(true, List.of()));
        var policy = policies().policies().getFirst();
        assertThrows(IllegalArgumentException.class, () -> new ExecutionGrantAuthorizationProperties(true, List.of(policy, policy)));
        assertThrows(IllegalArgumentException.class, () -> new ExecutionGrantAuthorizationProperties.Policy("shop", policy.purpose(),
                policy.resourceKey(), "/api/../admin", null, null, Set.of(START), Set.of(), Map.of(START, Set.of("tianji:agent:start"))));
        assertThrows(IllegalArgumentException.class, () -> new ExecutionGrantAuthorizationProperties.Policy("shop", policy.purpose(),
                policy.resourceKey(), policy.resourcePath(), policy.sessionResourceKey(), policy.sessionResourcePath(),
                Set.of(START), Set.of(READ), Map.of(START, Set.of("tianji:agent:start"))));
        assertThrows(IllegalArgumentException.class, () -> new ExecutionGrantAuthorizationProperties.Policy("shop", policy.purpose(),
                policy.resourceKey(), policy.resourcePath(), policy.sessionResourceKey(), null,
                Set.of(START), Set.of(READ), policy.permissionScopes()));
    }

    @Test void finite_authority_bindings_are_explicit_and_do_not_acquire_tokens_at_startup() {
        new org.springframework.boot.test.context.runner.ApplicationContextRunner()
                .withUserConfiguration(ExecutionGrantAuthorizationService.class)
                .run(context -> assertTrue(context.getBeansOfType(ExecutionGrantAuthorizationService.class).isEmpty()));
        var authority = new top.egon.cola.platform.tianquan.shoubing.starter.state.IdentityAuthorityProperties();
        authority.setBaseUri(URI.create("https://idp.example"));
        var configured = new top.egon.cola.platform.tianquan.shoubing.starter.state.IdentityAuthorityProperties.Binding();
        configured.setIssuer(ISSUER); configured.setSourceResource(RESOURCE); configured.setRegistrationId("registration");
        configured.setAudience(URI.create("https://idp.example/resource")); configured.setContext(ServiceTokenContext.TENANT);
        configured.setTenantId("20"); configured.setScopes(Set.of(
                top.egon.cola.platform.tianquan.shoubing.contract.state.IdentityAuthorityScopes.EXECUTION_GRANT_RESOLVE));
        authority.setBindings(Map.of("shop", configured));
        var starter = new top.egon.cola.platform.tianquan.shoubing.starter.autoconfigure.IdpStarterProperties();
        starter.setResourceUri(RESOURCE); starter.getServiceClient().setAppId("rbac-app");
        var oauth = mock(top.egon.cola.platform.tianquan.shoubing.starter.client.IdpServiceOAuth2Client.class);
        when(oauth.authorizationKey(any())).thenAnswer(inv -> {
            top.egon.cola.platform.tianquan.shoubing.starter.client.IdpServiceTokenRequest value = inv.getArgument(0);
            return new top.egon.cola.platform.tianquan.shoubing.starter.client.ServiceAuthorizationKey(ISSUER.toString(),
                    value.registrationId(), "rbac", 1, value.appId(), value.audience(), value.context(), value.tenantId(), value.scopes());
        });
        assertNotNull(new ExecutionGrantAuthorizationService(proofs, snapshots, policies(), authority, starter, issuers, oauth,
                new com.fasterxml.jackson.databind.ObjectMapper(), Clock.fixed(NOW, ZoneOffset.UTC)));
        verify(oauth, never()).authorize(any());
        new org.springframework.boot.test.context.runner.ApplicationContextRunner()
                .withUserConfiguration(EnabledConfiguration.class)
                .withPropertyValues("egon.tianquan-jianshen.execution-grants.enabled=true",
                        "egon.tianquan-jianshen.execution-grants.policies[0].system-code=shop",
                        "egon.tianquan-jianshen.execution-grants.policies[0].purpose=" + PURPOSE,
                        "egon.tianquan-jianshen.execution-grants.policies[0].resource-key=tianji.api.agent.start",
                        "egon.tianquan-jianshen.execution-grants.policies[0].resource-path=/api/tianji/v1/agent-runs",
                        "egon.tianquan-jianshen.execution-grants.policies[0].session-resource-key=tianji.api.agent.startSession",
                        "egon.tianquan-jianshen.execution-grants.policies[0].session-resource-path=/api/tianji/v1/agent-runs/with-session",
                        "egon.tianquan-jianshen.execution-grants.policies[0].required-permissions[0]=TIANJI_AGENT_START",
                        "egon.tianquan-jianshen.execution-grants.policies[0].session-permissions[0]=TIANJI_AGENT_READ",
                        "egon.tianquan-jianshen.execution-grants.policies[0].permission-scopes[TIANJI_AGENT_START][0]=tianji:agent:start",
                        "egon.tianquan-jianshen.execution-grants.policies[0].permission-scopes[TIANJI_AGENT_READ][0]=tianji:agent:read")
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
                    assertEquals(1, context.getBeansOfType(ExecutionGrantAuthorizationService.class).size());
                    assertEquals(Set.of(READ), context.getBean(ExecutionGrantAuthorizationProperties.class).policies().getFirst().sessionPermissions());
                });
        verify(oauth, never()).authorize(any());
        configured.setTenantId("21");
        assertThrows(IllegalStateException.class, () -> new ExecutionGrantAuthorizationService(proofs, snapshots, policies(), authority,
                starter, issuers, oauth, new com.fasterxml.jackson.databind.ObjectMapper(), Clock.fixed(NOW, ZoneOffset.UTC)));
    }

    @org.springframework.context.annotation.Configuration(proxyBeanMethods = false)
    @org.springframework.boot.context.properties.EnableConfigurationProperties(ExecutionGrantAuthorizationProperties.class)
    @org.springframework.context.annotation.Import(ExecutionGrantAuthorizationService.class)
    static class EnabledConfiguration { }

    private static ExecutionGrantAuthorizationProperties policies() {
        return new ExecutionGrantAuthorizationProperties(true, List.of(new ExecutionGrantAuthorizationProperties.Policy("shop",
                PURPOSE, "tianji.api.agent.start", "/api/tianji/v1/agent-runs",
                "tianji.api.agent.startSession", "/api/tianji/v1/agent-runs/with-session", Set.of(START), Set.of(READ),
                Map.of(START, Set.of("tianji:agent:start"), READ, Set.of("tianji:agent:read")))));
    }

    private static ExecutionGrantContract.Resolution grant(boolean session, Set<String> scopes) {
        return new ExecutionGrantContract.Resolution(ID, ISSUER.toString(), 20, "30", RESOURCE.toString(),
                new ExecutionGrantContract.Source("shop-runtime", "shop-client", "commerce", "shop", "test"),
                PURPOSE, INTENT, "c".repeat(64), session, NOW.plusSeconds(60), NOW.plusSeconds(600), scopes);
    }

    private static ExecutionGrantContract.Resolution copy(ExecutionGrantContract.Resolution original, String issuer, long tenant,
            String resource, ExecutionGrantContract.Source source, String purpose) {
        return new ExecutionGrantContract.Resolution(original.grantId(), issuer, tenant, original.subject(), resource, source, purpose,
                original.intentId(), original.bindingSha256(), original.sessionRequired(), original.expiresAt(), original.intentDeadlineAt(), original.scopes());
    }

    private static PermissionRuntimeSnapshotRepository.ExecutionView view(String key, Set<String> permissions, boolean session, Instant expiry) {
        var codes = permissions.stream().sorted().toList();
        var effective = new EffectivePermissionSnapshot(ISSUER.toString(), "30", SCOPE, "1", "2", "3",
                new EffectivePermissionSnapshot.ActiveRoleContext("shop", List.of("50"), List.of("50")), codes, expiry);
        var snapshot = new SystemAuthorizationSnapshot("20", "30", "60", "shop", 2, 3, List.of("50"), null, null,
                permissions, Set.of(key), Map.of(), Map.of(), "checksum", NOW, expiry, effective,
                new RuntimePolicyBinding("shop-java", "1", "a".repeat(64), "b".repeat(64), "c".repeat(64)));
        var resource = new PermissionManifest.ResourceDefinition(key, ResourceType.API,
                Map.of("methods", List.of("POST"), "paths", List.of(session ? "/api/tianji/v1/agent-runs/with-session" : "/api/tianji/v1/agent-runs")),
                ResourceAccess.PROTECTED, new PermissionRequirement(PermissionMode.ALL, session ? List.of(START, READ) : List.of(START)), null,
                List.of(PermissionManifest.PrincipalType.USER, PermissionManifest.PrincipalType.SERVICE),
                session ? List.of("tianji:agent:start", "tianji:agent:read") : List.of("tianji:agent:start"),
                new PermissionManifest.I18nReference("tianji", "start"), DefinitionLifecycle.ACTIVE);
        return new PermissionRuntimeSnapshotRepository.ExecutionView(snapshot, resource);
    }

    private static void assertDenied(Runnable action) {
        assertEquals("EXECUTION_GRANT_DENIED", assertThrows(Rbac3RuleViolation.class, action::run).reasonCode());
    }
    private static void assertUnavailable(Runnable action) {
        assertEquals("AUTH_RUNTIME_EXECUTION_UNAVAILABLE", assertThrows(Rbac3RuleViolation.class, action::run).reasonCode());
    }
}
