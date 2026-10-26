package top.egon.cola.platform.tianquan.jianshen.starter.permission;

import org.aopalliance.intercept.MethodInvocation;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.Test;
import org.springframework.mock.web.MockHttpServletRequest;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.web.context.request.RequestContextHolder;
import org.springframework.web.context.request.ServletRequestAttributes;
import top.egon.cola.platform.tianquan.jianshen.contract.permission.*;
import top.egon.cola.platform.tianquan.jianshen.contract.permission.annotation.*;
import top.egon.cola.platform.tianquan.jianshen.starter.authorization.AuthorizationService;
import top.egon.cola.platform.tianquan.jianshen.starter.cache.SingleFlightSnapshotLoader;
import top.egon.cola.platform.tianquan.jianshen.starter.client.Rbac3AuthorizationClient;
import top.egon.cola.platform.tianquan.jianshen.starter.security.*;
import top.egon.cola.platform.tianquan.shoubing.starter.security.VerifiedUserTokenCarrier;
import java.lang.reflect.*;
import java.util.*;
import static org.junit.jupiter.api.Assertions.*;
import static org.mockito.Mockito.*;
import static top.egon.cola.platform.tianquan.jianshen.starter.permission.PermissionRuntimeFixture.*;

class ApiRequirementEnforcementTest {
    @RequiresPermissions(codes="order:read")
    static class Handler {
        @PermissionResource(key="shop.api.update", type=ResourceType.API, labelPage="shop", labelKey="update")
        @RequiresPermissions(mode=PermissionMode.ANY, codes={"order:write","order:approve"})
        public void update() { }
    }
    private final PermissionRequirement rules = PermissionRequirement.allOf(List.of(all("order:read"),
            new PermissionRequirement(PermissionMode.ANY, List.of("order:write", "order:approve"))));
    private final PermissionManifest manifest = manifest(List.of(new PermissionManifest.ResourceDefinition("shop.api.update",
            ResourceType.API, Map.of("methods", List.of("POST"), "paths", List.of("/orders")), ResourceAccess.PROTECTED, rules,
            null, List.of(PermissionManifest.PrincipalType.USER), List.of(), new PermissionManifest.I18nReference("shop", "update"), DefinitionLifecycle.ACTIVE)));
    @AfterEach void clear() { SecurityContextHolder.clearContext(); RequestContextHolder.resetRequestAttributes(); }
    private Rbac3MethodAuthorizationManager manager(Set<String> granted) {
        authenticate(manifest, granted);
        var request = new MockHttpServletRequest(); VerifiedUserTokenCarrier.set(request, "original-verified-user-proof");
        RequestContextHolder.setRequestAttributes(new ServletRequestAttributes(request));
        Rbac3AuthorizationClient client = (system, user) -> snapshot(manifest, granted);
        var loader = new SingleFlightSnapshotLoader(client, "shop", CLOCK);
        return new Rbac3MethodAuthorizationManager(mock(AuthorizationService.class),
                new PermissionExecutionGuard(registry(manifest), new CurrentRbac3User(), loader));
    }
    private MethodInvocation invocation() throws Exception {
        var invocation = mock(MethodInvocation.class);
        when(invocation.getMethod()).thenReturn(Handler.class.getMethod("update"));
        when(invocation.getThis()).thenReturn(new Handler());
        return invocation;
    }
    @Test void typeAndMethodGroupsUseAndOfAnyWithoutFlattening() throws Exception {
        assertTrue(manager(Set.of("order:read", "order:approve")).check(
                () -> SecurityContextHolder.getContext().getAuthentication(), invocation()).isGranted());
        assertThrows(org.springframework.security.authorization.AuthorizationDeniedException.class,
                () -> manager(Set.of("order:approve")).check(() -> SecurityContextHolder.getContext().getAuthentication(), invocation()));
        assertThrows(org.springframework.security.authorization.AuthorizationDeniedException.class,
                () -> manager(Set.of("order:read")).check(() -> SecurityContextHolder.getContext().getAuthentication(), invocation()));
    }
    @Test void anyPermissionRequiresOnlyItsOwnScopeWhileTypeGroupsStayConjunctive() throws Exception {
        var policy = new top.egon.cola.platform.tianquan.jianshen.starter.autoconfigure.Rbac3StarterProperties.UserScopePolicyProperties()
                .setEnabled(true).setPermissionScopes(Map.of("order:read", Set.of("api:read"),
                        "order:write", Set.of("api:write"), "order:approve", Set.of("api:approve")));
        Set<String> granted = Set.of("order:read", "order:write", "order:approve");
        manager(granted);
        Rbac3AuthorizationClient client = (system, user) -> snapshot(manifest, granted);
        var manager = new Rbac3MethodAuthorizationManager(mock(AuthorizationService.class), new PermissionExecutionGuard(
                registry(manifest), new CurrentRbac3User(), new SingleFlightSnapshotLoader(client, "shop", CLOCK), null, policy));
        var details = new Rbac3UserDetails(USER, snapshot(manifest, granted));
        SecurityContextHolder.getContext().setAuthentication(new Rbac3AuthenticationToken(details, List.of(
                new org.springframework.security.core.authority.SimpleGrantedAuthority("SCOPE_api:read"),
                new org.springframework.security.core.authority.SimpleGrantedAuthority("SCOPE_api:approve"))));
        assertTrue(manager.check(() -> SecurityContextHolder.getContext().getAuthentication(), invocation()).isGranted());
        SecurityContextHolder.getContext().setAuthentication(new Rbac3AuthenticationToken(details, List.of(
                new org.springframework.security.core.authority.SimpleGrantedAuthority("SCOPE_api:read"))));
        assertThrows(org.springframework.security.authorization.AuthorizationDeniedException.class,
                () -> manager.check(() -> SecurityContextHolder.getContext().getAuthentication(), invocation()));
        policy.setPermissionScopes(Map.of("order:read", Set.of("api:read")));
        var missing = new PermissionExecutionGuard(registry(manifest), new CurrentRbac3User(), new SingleFlightSnapshotLoader(client, "shop", CLOCK), null, policy);
        assertThrows(org.springframework.security.authorization.AuthorizationDeniedException.class, () -> missing.require("shop.api.update"));
    }

    static class MixedHandler {
        @PermissionResource(key="shop.api.shared", type=ResourceType.API, labelPage="shop", labelKey="shared",
                allowedPrincipals={PermissionManifest.PrincipalType.USER, PermissionManifest.PrincipalType.SERVICE}, oauthScopes="machine:activate")
        @RequiresPermissions(codes="order:read")
        public void shared() { }
    }

    @Test void sharedApiKeepsUserScopeSeparateFromMachineScope() throws Exception {
        var mixed = manifest(List.of(new PermissionManifest.ResourceDefinition("shop.api.shared", ResourceType.API,
                Map.of("methods", List.of("POST"), "paths", List.of("/shared")), ResourceAccess.PROTECTED, all("order:read"), null,
                List.of(PermissionManifest.PrincipalType.USER, PermissionManifest.PrincipalType.SERVICE), List.of("machine:activate"),
                new PermissionManifest.I18nReference("shop", "shared"), DefinitionLifecycle.ACTIVE)));
        var registry = registry(mixed);
        var snapshot = snapshot(mixed, Set.of("order:read"));
        Rbac3AuthorizationClient client = new Rbac3AuthorizationClient() {
            @Override public top.egon.cola.platform.tianquan.jianshen.contract.authorization.SystemAuthorizationSnapshot fetch(String system,
                    top.egon.cola.platform.tianquan.shoubing.contract.IdentityPrincipal principal) { return snapshot; }
            @Override public top.egon.cola.platform.tianquan.jianshen.contract.authorization.ServicePolicySnapshot fetchPolicy(String system,
                    top.egon.cola.platform.tianquan.shoubing.contract.ServiceIdentityPrincipal principal) {
                return new top.egon.cola.platform.tianquan.jianshen.contract.authorization.ServicePolicySnapshot(SCOPE, "1", "3", snapshot.policyBinding(), snapshot.resourceCodes(), NOW.plusSeconds(30));
            }
        };
        var scopes = new top.egon.cola.platform.tianquan.jianshen.starter.autoconfigure.Rbac3StarterProperties.UserScopePolicyProperties()
                .setEnabled(true).setPermissionScopes(Map.of("order:read", Set.of("user:read")));
        var guard = new PermissionExecutionGuard(registry, new CurrentRbac3User(), new SingleFlightSnapshotLoader(client, "shop", CLOCK),
                new PermissionServicePolicyGuard(registry, client, "shop", CLOCK), scopes);
        var manager = new Rbac3MethodAuthorizationManager(mock(AuthorizationService.class), guard);
        var invocation = mock(MethodInvocation.class);
        when(invocation.getMethod()).thenReturn(MixedHandler.class.getMethod("shared")); when(invocation.getThis()).thenReturn(new MixedHandler());
        var request = new MockHttpServletRequest(); VerifiedUserTokenCarrier.set(request, "proof");
        RequestContextHolder.setRequestAttributes(new ServletRequestAttributes(request));
        var user = new Rbac3UserDetails(USER, snapshot);
        SecurityContextHolder.getContext().setAuthentication(new Rbac3AuthenticationToken(user,
                List.of(new org.springframework.security.core.authority.SimpleGrantedAuthority("SCOPE_user:read"))));
        assertTrue(manager.check(() -> SecurityContextHolder.getContext().getAuthentication(), invocation).isGranted());
        SecurityContextHolder.getContext().setAuthentication(new Rbac3AuthenticationToken(user,
                List.of(new org.springframework.security.core.authority.SimpleGrantedAuthority("SCOPE_machine:activate"))));
        assertThrows(org.springframework.security.authorization.AuthorizationDeniedException.class,
                () -> manager.check(() -> SecurityContextHolder.getContext().getAuthentication(), invocation));
        var service = new top.egon.cola.platform.tianquan.shoubing.contract.ServiceIdentityPrincipal("caller", "20", "caller", "41",
                java.net.URI.create("https://api.example/shop"), 0, Set.of("machine:activate"), "commerce", "caller", "test", "credential", NOW.minusSeconds(1), NOW.plusSeconds(60));
        SecurityContextHolder.getContext().setAuthentication(new top.egon.cola.platform.tianquan.shoubing.starter.security.IdpAuthenticationToken(
                service, List.of(), java.net.URI.create("https://idp.example/tenants/20")));
        assertTrue(manager.check(() -> SecurityContextHolder.getContext().getAuthentication(), invocation).isGranted());
    }

    @Test void mismatchedExecutingBuildCannotUseOtherwiseGrantedPermissions() {
        var snapshot = snapshot(manifest, Set.of("order:read", "order:approve"));
        var registry = new PermissionPolicyRegistry(manifest, "b".repeat(64), CLOCK, List.of(SCOPE));
        assertThrows(Rbac3AuthorizationClient.AuthorizationDeniedException.class, () -> registry.requireActive(snapshot, "shop.api.update"));
    }
    @Test void namespaceEnvironmentArePartOfTheTrustedBinding() {
        var wrong = new CatalogScope("10", "20", "commerce", "shop", "other", "production");
        var registry = new PermissionPolicyRegistry(manifest, ARTIFACT, CLOCK, List.of(wrong));
        assertThrows(Rbac3AuthorizationClient.AuthorizationDeniedException.class,
                () -> registry.requireActive(snapshot(manifest, Set.of("order:read", "order:approve")), "shop.api.update"));
    }
}
