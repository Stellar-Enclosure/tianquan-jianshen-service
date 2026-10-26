package top.egon.cola.platform.tianquan.jianshen.starter.security;

import com.fasterxml.jackson.databind.ObjectMapper;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.Test;
import org.springframework.mock.web.MockFilterChain;
import org.springframework.mock.web.MockHttpServletRequest;
import org.springframework.mock.web.MockHttpServletResponse;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.context.SecurityContextHolder;
import top.egon.cola.platform.tianquan.shoubing.contract.AuthenticationContext;
import top.egon.cola.platform.tianquan.shoubing.contract.IdentityPrincipal;
import top.egon.cola.platform.tianquan.shoubing.contract.ServiceIdentityPrincipal;
import top.egon.cola.platform.tianquan.shoubing.starter.security.IdpAuthenticationToken;
import top.egon.cola.platform.tianquan.jianshen.contract.authorization.SystemAuthorizationSnapshot;
import top.egon.cola.platform.tianquan.jianshen.starter.cache.SingleFlightSnapshotLoader;
import top.egon.cola.platform.tianquan.jianshen.starter.client.Rbac3AuthorizationClient;

import java.net.URI;
import java.time.Instant;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.concurrent.atomic.AtomicReference;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.verifyNoInteractions;
import static org.mockito.Mockito.when;

class Rbac3BearerAuthenticationFilterTest {

    private static final URI VERIFIED_ISSUER = URI.create("https://idp.example/tenants/1001");
    private static final Instant NOW = Instant.parse("2026-08-02T05:00:00Z");

    @AfterEach
    void clearContext() {
        SecurityContextHolder.clearContext();
    }

    @Test
    void neverTreatsTrustedIdentityHeadersAsAuthentication() throws Exception {
        SingleFlightSnapshotLoader loader = mock(SingleFlightSnapshotLoader.class);
        Rbac3BearerAuthenticationFilter filter = new Rbac3BearerAuthenticationFilter(
                loader, new ObjectMapper());
        MockHttpServletRequest request = new MockHttpServletRequest();
        request.addHeader("X-User-Id", "20001");
        MockFilterChain chain = new MockFilterChain();

        filter.doFilter(request, new MockHttpServletResponse(), chain);

        assertThat(chain.getRequest()).isSameAs(request);
        assertThat(SecurityContextHolder.getContext().getAuthentication()).isNull();
    }

    @Test
    void enrichesOnlyAnIdpAuthenticatedPrincipal() throws Exception {
        IdentityPrincipal principal = principal();
        SingleFlightSnapshotLoader loader = mock(SingleFlightSnapshotLoader.class);
        when(loader.load(principal)).thenReturn(snapshot());
        Rbac3BearerAuthenticationFilter filter = new Rbac3BearerAuthenticationFilter(
                loader, new ObjectMapper());
        SecurityContextHolder.getContext().setAuthentication(
                new IdpAuthenticationToken(principal, List.of(), VERIFIED_ISSUER));
        AtomicReference<Object> seenPrincipal = new AtomicReference<>();

        filter.doFilter(new MockHttpServletRequest(), new MockHttpServletResponse(),
                (request, response) -> seenPrincipal.set(
                        SecurityContextHolder.getContext().getAuthentication()
                                .getPrincipal()));

        assertThat(seenPrincipal.get()).isInstanceOf(Rbac3UserDetails.class);
        assertThat(((Rbac3UserDetails) seenPrincipal.get()).identity())
                .isEqualTo(principal);
        assertThat(SecurityContextHolder.getContext().getAuthentication()).isNull();
    }

    @Test
    void exposesOnlySnapshotPermissionsAsSpringAuthorities() throws Exception {
        IdentityPrincipal principal = principal();
        SingleFlightSnapshotLoader loader = mock(SingleFlightSnapshotLoader.class);
        when(loader.load(principal)).thenReturn(snapshot());
        Rbac3BearerAuthenticationFilter filter = new Rbac3BearerAuthenticationFilter(
                loader, new ObjectMapper());
        SecurityContextHolder.getContext().setAuthentication(
                new IdpAuthenticationToken(principal, List.of(), VERIFIED_ISSUER));
        AtomicReference<org.springframework.security.core.Authentication> seen =
                new AtomicReference<>();

        filter.doFilter(new MockHttpServletRequest(), new MockHttpServletResponse(),
                (request, response) -> seen.set(
                        SecurityContextHolder.getContext().getAuthentication()));

        assertThat(seen.get().getAuthorities())
                .extracting("authority")
                .containsExactlyInAnyOrder(
                        "TIANQUAN_JIANSHEN_payment:read", "CAP_payment:read");
        assertThat(seen.get().getName()).isEqualTo("alice-sub");
        assertThat(seen.get().getPrincipal()).isInstanceOf(Rbac3UserDetails.class);
    }

    @Test
    void preservesOnlyVerifiedScopeAuthoritiesAlongsideSnapshotPermissions()
            throws Exception {
        IdentityPrincipal principal = principal();
        SingleFlightSnapshotLoader loader = mock(SingleFlightSnapshotLoader.class);
        when(loader.load(principal)).thenReturn(snapshot());
        Rbac3BearerAuthenticationFilter filter = new Rbac3BearerAuthenticationFilter(
                loader, new ObjectMapper());
        SecurityContextHolder.getContext().setAuthentication(
                new IdpAuthenticationToken(principal, List.of(
                        new SimpleGrantedAuthority("SCOPE_finance:read"),
                        new SimpleGrantedAuthority("ROLE_ADMIN")), VERIFIED_ISSUER));
        AtomicReference<org.springframework.security.core.Authentication> seen =
                new AtomicReference<>();

        filter.doFilter(new MockHttpServletRequest(), new MockHttpServletResponse(),
                (request, response) -> seen.set(
                        SecurityContextHolder.getContext().getAuthentication()));

        assertThat(seen.get().getAuthorities())
                .extracting("authority")
                .contains("SCOPE_finance:read", "TIANQUAN_JIANSHEN_payment:read")
                .doesNotContain("ROLE_ADMIN");
        assertThat(((Rbac3UserDetails) seen.get().getPrincipal()).snapshot())
                .isEqualTo(snapshot());
    }

    @Test
    void leavesInternalRequestsForServiceAuthentication() throws Exception {
        SingleFlightSnapshotLoader loader = mock(SingleFlightSnapshotLoader.class);
        Rbac3BearerAuthenticationFilter filter = new Rbac3BearerAuthenticationFilter(
                loader, new ObjectMapper());
        SecurityContextHolder.getContext().setAuthentication(
                new IdpAuthenticationToken(principal()));
        var request = new MockHttpServletRequest(
                "GET", "/internal/v1/authorization/snapshots/current?systemCode=finance");
        var chain = new MockFilterChain();

        filter.doFilter(request, new MockHttpServletResponse(), chain);

        assertThat(chain.getRequest()).isSameAs(request);
        verifyNoInteractions(loader);
    }

    @Test
    void leavesServicePrincipalUnderIdpScopeAuthorizationWithoutLoadingRbac3()
            throws Exception {
        SingleFlightSnapshotLoader loader = mock(SingleFlightSnapshotLoader.class);
        Rbac3BearerAuthenticationFilter filter = new Rbac3BearerAuthenticationFilter(
                loader, new ObjectMapper());
        ServiceIdentityPrincipal principal = new ServiceIdentityPrincipal(
                "finance-service", "tenant-a", "finance-service", "token-1",
                URI.create("https://api.example/prod/permission/tianquan-jianshen"),
                12L, Set.of("service:participation:write"),
                "finance", "finance-web", "prod", "credential-1",
                NOW.minusSeconds(30), NOW.plusSeconds(300));
        SecurityContextHolder.getContext().setAuthentication(
                new IdpAuthenticationToken(principal, List.of(), VERIFIED_ISSUER));
        AtomicReference<Object> seenPrincipal = new AtomicReference<>();

        filter.doFilter(new MockHttpServletRequest(), new MockHttpServletResponse(),
                (request, response) -> seenPrincipal.set(
                        SecurityContextHolder.getContext().getAuthentication()
                                .getPrincipal()));

        assertThat(seenPrincipal).hasValue(principal);
        verifyNoInteractions(loader);
    }

    @Test
    void unavailableAuthorizationSnapshotReturnsServiceUnavailable() throws Exception {
        IdentityPrincipal principal = principal();
        SingleFlightSnapshotLoader loader = mock(SingleFlightSnapshotLoader.class);
        when(loader.load(principal)).thenThrow(
                new Rbac3AuthorizationClient.AuthorizationUnavailableException(
                        "TIANQUAN_JIANSHEN_UNAVAILABLE"));
        Rbac3BearerAuthenticationFilter filter = new Rbac3BearerAuthenticationFilter(
                loader, new ObjectMapper());
        SecurityContextHolder.getContext().setAuthentication(
                new IdpAuthenticationToken(principal, List.of(), VERIFIED_ISSUER));
        MockHttpServletResponse response = new MockHttpServletResponse();

        filter.doFilter(new MockHttpServletRequest(), response, new MockFilterChain());

        assertThat(response.getStatus()).isEqualTo(503);
        assertThat(response.getContentAsString()).contains("TIANQUAN_JIANSHEN_UNAVAILABLE");
    }

    private IdentityPrincipal principal() {
        return new IdentityPrincipal(
                "alice-sub", "1001", "token-1", Set.of("finance"),
                NOW.minusSeconds(30), NOW.plusSeconds(300),
                AuthenticationContext.password());
    }

    private SystemAuthorizationSnapshot snapshot() {
        var view = new top.egon.cola.platform.tianquan.jianshen.contract.permission.EffectivePermissionSnapshot(
                VERIFIED_ISSUER.toASCIIString(), "alice-sub",
                new top.egon.cola.platform.tianquan.jianshen.contract.permission.CatalogScope("10", "1001", "finance", "finance", "default", "test"),
                "1", "7", "11", new top.egon.cola.platform.tianquan.jianshen.contract.permission.EffectivePermissionSnapshot.ActiveRoleContext(
                        "finance", List.of("5001"), List.of("5001")), List.of("payment:read"), NOW.plusSeconds(300));
        return new SystemAuthorizationSnapshot("1001", "alice-sub", "101", "finance", 7, 11, List.of("5001"), null, null,
                Set.of("payment:read"), Set.of(), Map.of(), Map.of(), "sha256:fixture", NOW, NOW.plusSeconds(300), view,
                new top.egon.cola.platform.tianquan.jianshen.contract.authorization.RuntimePolicyBinding(
                        "finance-java", "1", "a".repeat(64), "b".repeat(64), "c".repeat(64)));
    }
}
