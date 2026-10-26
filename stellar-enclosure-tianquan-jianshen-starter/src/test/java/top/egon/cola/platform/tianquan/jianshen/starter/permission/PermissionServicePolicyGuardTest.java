package top.egon.cola.platform.tianquan.jianshen.starter.permission;

import com.fasterxml.jackson.databind.ObjectMapper;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.Test;
import org.springframework.mock.web.MockHttpServletRequest;
import org.springframework.mock.web.MockHttpServletResponse;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.context.SecurityContextHolder;
import top.egon.cola.platform.tianquan.jianshen.contract.authorization.RuntimePolicyBinding;
import top.egon.cola.platform.tianquan.jianshen.contract.authorization.ServicePolicySnapshot;
import top.egon.cola.platform.tianquan.jianshen.contract.permission.*;
import top.egon.cola.platform.tianquan.jianshen.starter.cache.SingleFlightSnapshotLoader;
import top.egon.cola.platform.tianquan.jianshen.starter.client.Rbac3AuthorizationClient;
import top.egon.cola.platform.tianquan.jianshen.starter.security.CurrentRbac3User;
import top.egon.cola.platform.tianquan.shoubing.contract.ServiceIdentityPrincipal;
import top.egon.cola.platform.tianquan.shoubing.starter.security.*;
import top.egon.cola.platform.tianquan.shoubing.starter.security.domain.TokenAuditProofBO;
import top.egon.cola.platform.tianquan.shoubing.starter.security.rpc.IdpRpcSecurityContext;

import java.net.URI;
import java.util.List;
import java.util.Map;
import java.util.Set;

import static org.junit.jupiter.api.Assertions.*;
import static org.mockito.ArgumentMatchers.*;
import static org.mockito.Mockito.*;
import static top.egon.cola.platform.tianquan.jianshen.starter.permission.PermissionRuntimeFixture.*;

class PermissionServicePolicyGuardTest {
    private static final URI ISSUER = URI.create("https://idp.example/tenants/20");
    private static final URI RESOURCE = URI.create("https://api.example/shop");
    private static final String KEY = "shop.api.read";
    private static final String SCOPE_CODE = "service:object:read";
    private final PermissionManifest manifest = manifest(List.of(new PermissionManifest.ResourceDefinition(KEY, ResourceType.API,
            Map.of("methods", List.of("GET"), "paths", List.of("/read")), ResourceAccess.PROTECTED, null, null,
            List.of(PermissionManifest.PrincipalType.SERVICE), List.of(SCOPE_CODE),
            new PermissionManifest.I18nReference("shop", "read"), DefinitionLifecycle.ACTIVE)));
    private final Rbac3AuthorizationClient client = mock(Rbac3AuthorizationClient.class);
    private final PermissionPolicyRegistry registry = registry(manifest);
    private final PermissionServicePolicyGuard policies = new PermissionServicePolicyGuard(registry, client, "shop", CLOCK);
    private final PermissionExecutionGuard execution = new PermissionExecutionGuard(registry, new CurrentRbac3User(),
            new SingleFlightSnapshotLoader(client, "shop", CLOCK), policies);

    @AfterEach
    void clear() { SecurityContextHolder.clearContext(); }

    @Test
    void ordinaryProtectedServiceCannotFetchPolicyWithAnArbitraryAuthenticationToken() {
        var caller = caller("caller", Set.of(SCOPE_CODE));
        var fake = UsernamePasswordAuthenticationToken.authenticated(caller, "", List.of());
        fake.setDetails(proof());
        SecurityContextHolder.getContext().setAuthentication(fake);
        assertThrows(org.springframework.security.authorization.AuthorizationDeniedException.class, () -> execution.requireExecution(KEY));
        assertThrows(Rbac3AuthorizationClient.AuthorizationDeniedException.class, () -> policies.require(caller, KEY));
        verifyNoInteractions(client);
    }

    @Test
    void missingVerifiedIssuerCannotBeReplacedByDetachedAuditMetadata() {
        var caller = caller("caller", Set.of(SCOPE_CODE));
        var authentication = new IdpAuthenticationToken(caller);
        authentication.setDetails(proof());
        SecurityContextHolder.getContext().setAuthentication(authentication);
        assertThrows(Rbac3AuthorizationClient.AuthorizationDeniedException.class, () -> policies.require(caller, KEY));
        verifyNoInteractions(client);
    }

    @Test
    void anotherHttpCallerCannotSupplyThePolicyRequestIdentity() {
        var first = caller("first", Set.of(SCOPE_CODE));
        var second = caller("second", Set.of(SCOPE_CODE));
        SecurityContextHolder.getContext().setAuthentication(new IdpAuthenticationToken(first, List.of(), ISSUER));
        assertThrows(Rbac3AuthorizationClient.AuthorizationDeniedException.class, () -> policies.require(second, KEY));
        verifyNoInteractions(client);
    }

    @Test
    void rpcProofCannotBeBorrowedByAnotherSpringCaller() {
        var first = caller("first", Set.of(SCOPE_CODE));
        var second = caller("second", Set.of(SCOPE_CODE));
        var proof = proof();
        IdpRpcSecurityContext.with(first, "verified-service-token", proof, null).run(() ->
                IdpRpcSecurityContext.runWithSpringSecurity(second, second.scopes(), proof, () ->
                        assertThrows(Rbac3AuthorizationClient.AuthorizationDeniedException.class, () -> policies.require(second, KEY))));
        verifyNoInteractions(client);
        assertNull(SecurityContextHolder.getContext().getAuthentication());
    }

    @Test
    void realHttpAuthenticationAdapterCarriesTheVerifiedIssuerForTheCurrentCaller() throws Exception {
        var caller = caller("caller", Set.of(SCOPE_CODE));
        when(client.fetchPolicy("shop", caller)).thenReturn(policy());
        var services = mock(ServiceAccessTokenVerifier.class);
        when(services.verify("verified-service-token")).thenReturn(new AccessTokenVerification.Valid<>(caller, caller.scopes(), proof(), ISSUER));
        var filter = new IdpBearerAuthenticationFilter(mock(UserAccessTokenVerifier.class), services,
                new IdpEndpointAuthenticationPolicy(List.of(), List.of("/read")), new ObjectMapper());
        var request = new MockHttpServletRequest("GET", "/read");
        request.addHeader("Authorization", "Bearer verified-service-token");
        var response = new MockHttpServletResponse();
        boolean[] reached = {false};
        filter.doFilter(request, response, (input, output) -> {
            execution.requireExecution(KEY);
            reached[0] = true;
        });
        assertTrue(reached[0]);
        assertEquals(200, response.getStatus());
        verify(client).fetchPolicy("shop", caller);
        assertNull(SecurityContextHolder.getContext().getAuthentication());
    }

    @Test
    void realRpcContextAdapterKeepsItsProofBoundToTheCurrentCaller() throws Exception {
        var caller = caller("caller", Set.of(SCOPE_CODE));
        when(client.fetchPolicy("shop", caller)).thenReturn(policy());
        var proof = proof();
        IdpRpcSecurityContext.with(caller, "verified-service-token", proof, null).run(() ->
                IdpRpcSecurityContext.runWithSpringSecurity(caller, caller.scopes(), proof, () -> execution.requireExecution(KEY)));
        verify(client).fetchPolicy("shop", caller);
        assertNull(SecurityContextHolder.getContext().getAuthentication());
    }

    @Test
    void verifiedIdentityStillNeedsTheDeclaredScopeAndMatchingTenantArtifactAndCurrentPolicy() throws Exception {
        var caller = caller("caller", Set.of("service:other"));
        SecurityContextHolder.getContext().setAuthentication(new IdpAuthenticationToken(caller, List.of(), ISSUER));
        assertThrows(org.springframework.security.authorization.AuthorizationDeniedException.class, () -> execution.requireExecution(KEY));
        verifyNoInteractions(client);
        caller = caller("caller", Set.of(SCOPE_CODE));
        SecurityContextHolder.getContext().setAuthentication(new IdpAuthenticationToken(caller, List.of(), ISSUER));
        var valid = policy();
        for (var denied : List.of(
                new ServicePolicySnapshot(new CatalogScope("10", "21", "commerce", "shop", "default", "test"), "1", "3", valid.policyBinding(), valid.resourceKeys(), valid.expiresAt()),
                new ServicePolicySnapshot(SCOPE, "1", "3", new RuntimePolicyBinding("shop-java", "1", "b".repeat(64), valid.policyBinding().policyDigest(), valid.policyBinding().manifestDigest()), valid.resourceKeys(), valid.expiresAt()),
                new ServicePolicySnapshot(SCOPE, "1", "3", valid.policyBinding(), valid.resourceKeys(), NOW.minusSeconds(1)))) {
            when(client.fetchPolicy("shop", caller)).thenReturn(denied);
            assertThrows(org.springframework.security.authorization.AuthorizationDeniedException.class, () -> execution.requireExecution(KEY));
        }
    }

    private ServiceIdentityPrincipal caller(String clientId, Set<String> scopes) {
        return new ServiceIdentityPrincipal(clientId, "20", clientId, "41", RESOURCE, 0, scopes,
                "commerce", "caller", "test", "credential", NOW.minusSeconds(10), NOW.plusSeconds(60));
    }

    private TokenAuditProofBO proof() { return new TokenAuditProofBO(ISSUER, RESOURCE, null, "b".repeat(64), "c".repeat(64)); }

    private ServicePolicySnapshot policy() {
        var digests = new PermissionManifestCanonicalizer().digests(manifest);
        return new ServicePolicySnapshot(SCOPE, "1", "3", new RuntimePolicyBinding("shop-java", "1", ARTIFACT,
                digests.policyDigest(), digests.manifestDigest()), Set.of(KEY), NOW.plusSeconds(30));
    }
}
