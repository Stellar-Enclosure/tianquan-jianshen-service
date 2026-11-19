package top.egon.cola.platform.tianquan.jianshen.admin.config.runtime;

import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.Test;
import org.springframework.security.access.AccessDeniedException;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import top.egon.cola.component.rpc.consumer.interceptor.RpcClientInvocation;
import top.egon.cola.component.rpc.consumer.reference.RpcServiceTargetVO;
import top.egon.cola.platform.tianquan.jianshen.admin.shared.tenant.domain.TenantContext;
import top.egon.cola.platform.tianquan.jianshen.contract.authorization.SystemAuthorizationSnapshot;
import top.egon.cola.platform.tianquan.jianshen.starter.security.Rbac3AuthenticationToken;
import top.egon.cola.platform.tianquan.jianshen.starter.security.Rbac3UserDetails;
import top.egon.cola.platform.tianquan.shoubing.contract.AuthenticationContext;
import top.egon.cola.platform.tianquan.shoubing.contract.IdentityPrincipal;
import top.egon.cola.platform.tianquan.shoubing.rpc.contract.IdentityDirectoryRpc;
import top.egon.cola.platform.tianquan.shoubing.rpc.contract.proto.v1.IdentityDirectoryServiceGrpc;
import top.egon.cola.platform.tianquan.shoubing.starter.security.domain.TokenAuditProofBO;

import java.net.URI;
import java.time.Clock;
import java.time.Instant;
import java.time.ZoneOffset;
import java.util.List;
import java.util.Map;
import java.util.Set;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.when;

class Rbac3IdentityDirectoryTenantResolverTest {

    private static final Instant NOW = Instant.parse("2026-11-18T03:00:00Z");
    private static final String ISSUER = "https://identity.example.test/tenant-a";
    private static final String RESOURCE = "https://api.example.test/jianshen";
    private static final String MEMBERSHIP = IdentityDirectoryServiceGrpc.getGetTenantMembershipMethod().getFullMethodName();
    private static final Set<String> PLATFORM_PERMISSIONS = Set.of("system:platform:admin", "system:tenant:target");

    private final Rbac3IdentityDirectoryTenantResolver resolver =
            new Rbac3IdentityDirectoryTenantResolver(Clock.fixed(NOW, ZoneOffset.UTC));

    @AfterEach
    void clearTenantContext() {
        TenantContext.clear();
    }

    @Test
    void resolvesTheAuthorizedTenantFromTheVerifiedJianshenRequestContext() {
        var external = user(Set.of());
        TenantContext.set(new TenantContext("tenant-a", "tenant-a", false));
        assertThat(resolver.resolve(invocation("shoubing-identity-directory", MEMBERSHIP), external)).contains("tenant-a");

        var platform = user(PLATFORM_PERMISSIONS);
        TenantContext.set(new TenantContext("tenant-a", "tenant-b", true));
        assertThat(resolver.resolve(invocation("shoubing-identity-directory", MEMBERSHIP), platform)).contains("tenant-b");
    }

    @Test
    void rejectsUnprovedOrMismatchedTenantAndInsufficientPlatformPermissions() {
        var target = invocation("shoubing-identity-directory", MEMBERSHIP);
        var caller = user(Set.of());
        TenantContext.set(new TenantContext("tenant-b", "tenant-b", false));
        assertDenied(target, caller);
        TenantContext.set(new TenantContext("tenant-a", "tenant-b", false));
        assertDenied(target, caller);
        TenantContext.set(new TenantContext("tenant-a", "tenant-b", true));
        assertDenied(target, user(Set.of("system:tenant:target")));
        assertDenied(target, user(Set.of("system:platform:admin")));
        TenantContext.set(new TenantContext("tenant-a", "tenant-a", false));
        var unproved = user(PLATFORM_PERMISSIONS);
        unproved.setDetails(null);
        assertDenied(target, unproved);
        var arbitrary = UsernamePasswordAuthenticationToken.authenticated(caller.getPrincipal(), "", List.of());
        assertDenied(target, arbitrary);
    }

    @Test
    void neverOffersTheJianshenTenantForAnUnrelatedNativeBindingOrMethod() {
        var caller = user(PLATFORM_PERMISSIONS);
        TenantContext.set(new TenantContext("tenant-a", "tenant-b", true));
        assertThat(resolver.resolve(invocation("other-binding", MEMBERSHIP), caller)).isEmpty();
        assertThat(resolver.resolve(invocation("shoubing-identity-directory",
                IdentityDirectoryServiceGrpc.SERVICE_NAME + "/OtherRead"), caller)).isEmpty();
    }

    private static RpcClientInvocation invocation(String binding, String method) {
        var invocation = mock(RpcClientInvocation.class);
        when(invocation.target()).thenReturn(new RpcServiceTargetVO(binding, 1,
                "permission-prod", "tianquan-shoubing-rpc", 18122, Set.of(method)));
        when(invocation.serviceName()).thenReturn(IdentityDirectoryServiceGrpc.SERVICE_NAME);
        when(invocation.group()).thenReturn(IdentityDirectoryRpc.GROUP);
        when(invocation.version()).thenReturn(IdentityDirectoryRpc.VERSION);
        when(invocation.fullMethodName()).thenReturn(method);
        return invocation;
    }

    private static Rbac3AuthenticationToken user(Set<String> permissions) {
        var principal = new IdentityPrincipal("user", "tenant-a", "issuer-token", Set.of(RESOURCE),
                NOW.minusSeconds(1), NOW.plusSeconds(60), AuthenticationContext.of("PASSWORD", NOW.minusSeconds(1)));
        var snapshot = new SystemAuthorizationSnapshot("tenant-a", "user", "17", "tianquan-jianshen-admin",
                1L, 1L, List.of(), permissions, Map.of(), Map.of(), "sha256:fixture", NOW, NOW.plusSeconds(60));
        var token = new Rbac3AuthenticationToken(new Rbac3UserDetails(principal, snapshot));
        token.setDetails(new TokenAuditProofBO(URI.create(ISSUER), URI.create(RESOURCE), null, null, null));
        return token;
    }

    private void assertDenied(RpcClientInvocation invocation, Authentication authentication) {
        assertThatThrownBy(() -> resolver.resolve(invocation, authentication))
                .isInstanceOf(AccessDeniedException.class);
    }
}
