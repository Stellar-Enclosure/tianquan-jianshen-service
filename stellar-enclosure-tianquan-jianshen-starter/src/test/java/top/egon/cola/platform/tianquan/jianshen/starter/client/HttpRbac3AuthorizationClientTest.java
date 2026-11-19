package top.egon.cola.platform.tianquan.jianshen.starter.client;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.datatype.jsr310.JavaTimeModule;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.Test;
import org.springframework.mock.web.MockHttpServletRequest;
import org.springframework.web.context.request.RequestContextHolder;
import org.springframework.web.context.request.ServletRequestAttributes;
import top.egon.cola.platform.tianquan.shoubing.contract.AuthenticationContext;
import top.egon.cola.platform.tianquan.shoubing.contract.IdentityPrincipal;
import top.egon.cola.platform.tianquan.shoubing.starter.security.VerifiedUserTokenCarrier;

import java.net.URI;
import java.time.Clock;
import java.time.Duration;
import java.time.Instant;
import java.util.Set;
import java.util.List;
import java.util.Map;
import java.util.concurrent.atomic.AtomicReference;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

class HttpRbac3AuthorizationClientTest {

    @AfterEach
    void clearRequest() {
        RequestContextHolder.resetRequestAttributes();
    }

    @Test
    void fetchUsesBoundContextPathAndBothExplicitCredentials() throws Exception {
        AtomicReference<URI> requestedUri = new AtomicReference<>();
        AtomicReference<String> requestedServiceToken = new AtomicReference<>();
        AtomicReference<String> requestedUserToken = new AtomicReference<>();
        HttpRbac3AuthorizationClient.Transport transport =
                (uri, serviceToken, userToken, timeout) -> {
                    requestedUri.set(uri);
                    requestedServiceToken.set(serviceToken);
                    requestedUserToken.set(userToken);
                    return new HttpRbac3AuthorizationClient.HttpResponse(200, responseBody());
                };
        setVerifiedUserToken("user-at");
        HttpRbac3AuthorizationClient client = client(transport);

        var snapshot = client.fetch("finance", principal());

        assertThat(snapshot.identitySub()).isEqualTo("alice-sub");
        assertThat(requestedUri.get().toString()).isEqualTo(
                "http://127.0.0.1:8088/internal/v1/authorization/snapshots/current"
                        + "?systemCode=finance");
        assertThat(requestedServiceToken).hasValue("service-token");
        assertThat(requestedUserToken).hasValue("user-at");
    }

    @Test
    void fetchSelectsServiceCredentialForTheExactTargetTenant() throws Exception {
        AtomicReference<String> requestedTenant = new AtomicReference<>();
        HttpTenantServiceTokenSupplier supplier = supplier(tenantId -> {
            requestedTenant.set(tenantId);
            return "service-token-for-" + tenantId;
        });
        setVerifiedUserToken("user-at");
        HttpRbac3AuthorizationClient client = new HttpRbac3AuthorizationClient(
                URI.create("http://127.0.0.1:8088"), supplier,
                Duration.ofSeconds(1), objectMapper(),
                (uri, serviceToken, userToken, timeout) ->
                        new HttpRbac3AuthorizationClient.HttpResponse(200, responseBody()));

        client.fetch("finance", principal());

        assertThat(requestedTenant).hasValue("tenant-a");
    }

    @Test
    void fetchAcceptsExplicitUserTokenOutsideServletRequestContext()
            throws Exception {
        AtomicReference<String> requestedUserToken = new AtomicReference<>();
        HttpRbac3AuthorizationClient client = client(
                (uri, serviceToken, userToken, timeout) -> {
                    requestedUserToken.set(userToken);
                    return new HttpRbac3AuthorizationClient.HttpResponse(
                            200,
                            responseBody()
                    );
                });

        client.fetch("finance", principal(), "explicit-user-at");

        assertThat(requestedUserToken).hasValue("explicit-user-at");
    }

    @Test
    void deniedAndTransientStatusesAreClassifiedWithoutLeakingCredential()
            throws Exception {
        setVerifiedUserToken("do-not-leak-user-token");
        HttpRbac3AuthorizationClient denied = client(
                (uri, serviceToken, userToken, timeout) ->
                        new HttpRbac3AuthorizationClient.HttpResponse(403, "{}"));
        HttpRbac3AuthorizationClient unavailable = client(
                (uri, serviceToken, userToken, timeout) ->
                        new HttpRbac3AuthorizationClient.HttpResponse(502, "{}"));

        assertThatThrownBy(() -> denied.fetch("finance", principal()))
                .isInstanceOf(Rbac3AuthorizationClient.AuthorizationDeniedException.class)
                .hasMessage("TIANQUAN_JIANSHEN_AUTHORIZATION_DENIED")
                .hasMessageNotContaining("do-not-leak-user-token");
        assertThatThrownBy(() -> unavailable.fetch("finance", principal()))
                .isInstanceOf(Rbac3AuthorizationClient.AuthorizationUnavailableException.class)
                .hasMessage("TIANQUAN_JIANSHEN_AUTHORIZATION_UNAVAILABLE")
                .hasMessageNotContaining("do-not-leak-user-token");
    }

    @Test
    void rejectsClearTextNonLoopbackEndpoint() {
        assertThatThrownBy(() -> new HttpRbac3AuthorizationClient(
                URI.create("http://tianquan-jianshen.internal"), supplier(ignored -> "token"),
                Duration.ofSeconds(1), objectMapper(),
                (uri, serviceToken, userToken, timeout) -> null))
                .isInstanceOf(IllegalArgumentException.class)
                .hasMessageContaining("HTTPS");
    }

    @Test
    void runtimeRequestPropagatesTheCurrentTraceWithoutInventingOne() {
        var uri = URI.create("https://authorization.example/internal");
        assertThat(HttpRbac3AuthorizationClient.request(uri, "service", "user", Duration.ofSeconds(1))
                .headers().firstValue("traceparent")).isEmpty();
        assertThat(HttpRbac3AuthorizationClient.request(URI.create("http://authorization.apps.svc.cluster.local/internal"),
                "service", "user", Duration.ofSeconds(1)).version()).contains(java.net.http.HttpClient.Version.HTTP_1_1);
        var trace = top.egon.cola.component.common.trace.TraceContext.root();
        try (var ignored = trace.open()) {
            var request = HttpRbac3AuthorizationClient.request(uri, "service", "user", Duration.ofSeconds(1));
            assertThat(request.headers().firstValue("traceparent")).hasValueSatisfying(value ->
                    assertThat(value).startsWith("00-" + trace.traceId() + "-"));
            assertThat(request.headers().firstValue("X-Egon-Subject-Token")).hasValue("user");
        }
    }

    @Test
    void delegatedFetchUsesTheVerifiedServiceTenantAndRejectsAnotherCatalog() throws Exception {
        var now = Instant.now();
        var scope = new top.egon.cola.platform.tianquan.jianshen.contract.permission.CatalogScope("10", "20", "trade", "shop", "default", "test");
        var view = new top.egon.cola.platform.tianquan.jianshen.contract.permission.EffectivePermissionSnapshot(
                "https://idp.example/tenants/20", "alice", scope, "1", "2", "3",
                new top.egon.cola.platform.tianquan.jianshen.contract.permission.EffectivePermissionSnapshot.ActiveRoleContext("shop", List.of("7"), List.of("7")),
                List.of("shop:read"), now.plusSeconds(60));
        var binding = new top.egon.cola.platform.tianquan.jianshen.contract.authorization.RuntimePolicyBinding(
                "shop-java", "1", "a".repeat(64), "b".repeat(64), "c".repeat(64));
        var snapshot = new top.egon.cola.platform.tianquan.jianshen.contract.authorization.SystemAuthorizationSnapshot(
                "20", "alice", "30", "shop", 2, 3, List.of("7"), null, null, Set.of("shop:read"), Set.of(),
                Map.of(), Map.of(), "checksum", now, view.snapshotExpiresAt(), view, binding);
        String body = objectMapper().writeValueAsString(Map.of("data", snapshot));
        AtomicReference<String> sent = new AtomicReference<>();
        HttpRbac3AuthorizationClient client = client((uri, service, user, timeout) -> {
            sent.set(user); return new HttpRbac3AuthorizationClient.HttpResponse(200, body);
        });
        assertThatThrownBy(() -> client.fetchDelegated("shop", "9999999999999999999", "user-proof"))
                .isInstanceOf(Rbac3AuthorizationClient.AuthorizationDeniedException.class)
                .hasMessage("DELEGATED_TENANT_INVALID");
        assertThat(sent).hasValue(null);
        assertThat(client.fetchDelegated("shop", "20", "user-proof").identitySub()).isEqualTo("alice");
        assertThat(sent).hasValue("user-proof");
        assertThatThrownBy(() -> client.fetchDelegated("shop", "21", "user-proof"))
                .isInstanceOf(Rbac3AuthorizationClient.AuthorizationDeniedException.class)
                .hasMessage("DELEGATED_USER_VIEW_BINDING_MISMATCH");
    }

    private static final URI MANAGED_ISSUER = URI.create("https://idp.example/20");
    private static final URI MANAGED_ENDPOINT = URI.create("https://jianshen.example");
    private static final URI MANAGED_RESOURCE = URI.create("https://jianshen.example/api");
    private static final String SNAPSHOT_PATH = "/internal/v1/authorization/snapshots/current";
    private static final String POLICY_PATH = "/internal/v1/authorization/policies/current";
    private static final Set<String> MANAGED_SCOPES = Set.of("service:authorization:snapshot", "service:authorization:policy");

    @Test void explicitManagedConstructorCannotSilentlySelectLegacyModeWithNullIdentityOrRegistry() {
        var fixture = new ManagedFixture();
        assertThatThrownBy(() -> new HttpRbac3AuthorizationClient(MANAGED_ENDPOINT, fixture.supplier, Duration.ofSeconds(1),
                objectMapper(), null, null)).isInstanceOf(NullPointerException.class);
        assertThatThrownBy(() -> new HttpRbac3AuthorizationClient(MANAGED_ENDPOINT, fixture.supplier, Duration.ofSeconds(1),
                objectMapper(), "yaoguang", null)).isInstanceOf(NullPointerException.class);
    }

    @Test void managedAllThreeCallsUseOnlyTheFixedApprovedGetTargetsAndCanonicalAudience() throws Exception {
        var fixture = new ManagedFixture();
        var calls = new java.util.ArrayList<URI>();
        var subjects = new java.util.ArrayList<String>();
        var client = fixture.client("yaoguang", fixture.routes(), (uri, service, user, budget) -> {
            calls.add(uri); subjects.add(user);
            assertThat(service).isEqualTo("managed-service-at");
            assertThat(budget).isPositive().isLessThanOrEqualTo(Duration.ofSeconds(1));
            return new HttpRbac3AuthorizationClient.HttpResponse(200,
                    uri.getPath().equals(POLICY_PATH) ? fixture.policyBody("yaoguang") : fixture.snapshotBody("yaoguang"));
        });
        org.mockito.Mockito.verify(fixture.oauth, org.mockito.Mockito.never()).authorizeBounded(
                org.mockito.ArgumentMatchers.any(), org.mockito.ArgumentMatchers.anyString(), org.mockito.ArgumentMatchers.any());
        assertThat(client.fetch("yaoguang", fixture.user(), "original-user-at").tenantId()).isEqualTo("20");
        assertThat(client.fetchDelegated("yaoguang", "20", "delegated-user-at").tenantId()).isEqualTo("20");
        assertThat(client.fetchPolicy("yaoguang", fixture.service()).catalogScope().tenantId()).isEqualTo("20");
        assertThat(calls).containsExactly(
                URI.create("http://jianshen.auth-system.svc.cluster.local:8080" + SNAPSHOT_PATH + "?systemCode=yaoguang"),
                URI.create("http://jianshen.auth-system.svc.cluster.local:8080" + SNAPSHOT_PATH + "?systemCode=yaoguang"),
                URI.create("http://jianshen.auth-system.svc.cluster.local:8080" + POLICY_PATH + "?systemCode=yaoguang"));
        assertThat(subjects).containsExactly("original-user-at", "delegated-user-at", null);
        var capture = org.mockito.ArgumentCaptor.forClass(top.egon.cola.platform.tianquan.shoubing.starter.client.IdpServiceTokenRequest.class);
        org.mockito.Mockito.verify(fixture.oauth, org.mockito.Mockito.times(3)).authorizeBounded(capture.capture(),
                org.mockito.ArgumentMatchers.eq(MANAGED_ISSUER.toString()), org.mockito.ArgumentMatchers.any());
        assertThat(capture.getAllValues()).allSatisfy(request -> {
            assertThat(request.audience()).isEqualTo(MANAGED_RESOURCE);
            assertThat(request.registrationId()).isEqualTo("yaoguang-auth");
            assertThat(request.appId()).isEqualTo("yaoguang-app");
            assertThat(request.tenantId()).isEqualTo("20");
            assertThat(request.context()).isEqualTo(top.egon.cola.platform.tianquan.shoubing.contract.ServiceTokenContext.TENANT);
            assertThat(request.scopes()).isEqualTo(MANAGED_SCOPES);
        });
        org.mockito.Mockito.verify(fixture.oauth, org.mockito.Mockito.never()).authorize(org.mockito.ArgumentMatchers.any());
    }

    @Test void managedSystemCodeIsRevalidatedBeforeAnyTokenOrNetworkAndEncodedAsOneQueryValue() throws Exception {
        var fixture = new ManagedFixture(); var sent = new AtomicReference<URI>();
        var code = "yaoguang &alpha?=中文";
        var client = fixture.client(code, fixture.routes(), (uri, token, user, timeout) -> {
            sent.set(uri); return new HttpRbac3AuthorizationClient.HttpResponse(403, "{}");
        });
        assertThatThrownBy(() -> client.fetch("other", fixture.user(), "user-at"))
                .isInstanceOf(Rbac3AuthorizationClient.AuthorizationDeniedException.class);
        assertThat(sent).hasValue(null);
        org.mockito.Mockito.verify(fixture.oauth, org.mockito.Mockito.never()).authorizeBounded(
                org.mockito.ArgumentMatchers.any(), org.mockito.ArgumentMatchers.anyString(), org.mockito.ArgumentMatchers.any());
        assertThatThrownBy(() -> client.fetch(code, fixture.user(), "user-at"))
                .isInstanceOf(Rbac3AuthorizationClient.AuthorizationDeniedException.class);
        assertThat(sent.get().getRawQuery()).isEqualTo("systemCode=" + java.net.URLEncoder.encode(code, java.nio.charset.StandardCharsets.UTF_8));
        assertThat(sent.get().getRawQuery().chars().filter(value -> value == '&').count()).isZero();
    }

    @Test void managedMissingOrMismatchedEitherRouteCannotFallBackOrObtainAToken() {
        var fixture = new ManagedFixture();
        var bad = java.util.List.of(
                top.egon.cola.platform.tianquan.shoubing.starter.client.IdpTransportBindingRegistry.empty(),
                new top.egon.cola.platform.tianquan.shoubing.starter.client.IdpTransportBindingRegistry(List.of(fixture.route("snap", SNAPSHOT_PATH, MANAGED_ISSUER, MANAGED_RESOURCE, "yaoguang-auth", "GET"))),
                new top.egon.cola.platform.tianquan.shoubing.starter.client.IdpTransportBindingRegistry(List.of(
                        fixture.route("snap", SNAPSHOT_PATH, MANAGED_ISSUER, MANAGED_RESOURCE, "yaoguang-auth", "GET"),
                        fixture.route("policy", POLICY_PATH, URI.create("https://idp.example/21"), MANAGED_RESOURCE, "yaoguang-auth", "GET"))),
                new top.egon.cola.platform.tianquan.shoubing.starter.client.IdpTransportBindingRegistry(List.of(
                        fixture.route("snap", SNAPSHOT_PATH, MANAGED_ISSUER, MANAGED_RESOURCE, "yaoguang-auth", "GET"),
                        fixture.route("policy", POLICY_PATH, MANAGED_ISSUER, URI.create("https://other.example/api"), "yaoguang-auth", "GET"))),
                new top.egon.cola.platform.tianquan.shoubing.starter.client.IdpTransportBindingRegistry(List.of(
                        fixture.route("snap", SNAPSHOT_PATH, MANAGED_ISSUER, MANAGED_RESOURCE, "yaoguang-auth", "GET"),
                        fixture.route("policy", POLICY_PATH, MANAGED_ISSUER, MANAGED_RESOURCE, "other-auth", "GET"))),
                new top.egon.cola.platform.tianquan.shoubing.starter.client.IdpTransportBindingRegistry(List.of(
                        fixture.route("snap", SNAPSHOT_PATH, MANAGED_ISSUER, MANAGED_RESOURCE, "yaoguang-auth", "GET"),
                        fixture.route("policy", POLICY_PATH, MANAGED_ISSUER, MANAGED_RESOURCE, "yaoguang-auth", "POST"))));
        for (var routes : bad) assertThatThrownBy(() -> fixture.client("yaoguang", routes,
                (uri, token, user, timeout) -> { throw new AssertionError("unapproved transport dispatched"); }))
                .isInstanceOf(IllegalStateException.class).hasMessageNotContaining("managed-service-at");
        org.mockito.Mockito.verify(fixture.oauth, org.mockito.Mockito.never()).authorizeBounded(
                org.mockito.ArgumentMatchers.any(), org.mockito.ArgumentMatchers.anyString(), org.mockito.ArgumentMatchers.any());
    }

    @Test void managedSingleRegistrationStillRevalidatesBothTargetsBeforeTokenAtRequestBoundary() {
        var fixture = new ManagedFixture(); fixture.properties.getServiceClient().setTenantRegistrationIds(Map.of());
        var incomplete = new top.egon.cola.platform.tianquan.shoubing.starter.client.IdpTransportBindingRegistry(List.of(
                fixture.route("snap", SNAPSHOT_PATH, MANAGED_ISSUER, MANAGED_RESOURCE, "yaoguang-auth", "GET")));
        var client = fixture.client("yaoguang", incomplete,
                (uri, token, user, timeout) -> { throw new AssertionError("unapproved transport dispatched"); });
        assertThatThrownBy(() -> client.fetch("yaoguang", fixture.user(), "user-at"))
                .isInstanceOf(Rbac3AuthorizationClient.AuthorizationUnavailableException.class).hasCause(null);
        org.mockito.Mockito.verify(fixture.oauth, org.mockito.Mockito.never()).authorizeBounded(
                org.mockito.ArgumentMatchers.any(), org.mockito.ArgumentMatchers.anyString(), org.mockito.ArgumentMatchers.any());
    }

    @Test void managedTransportFailuresRetainDenialVsUnavailableAndNeverExposePrivateCause() {
        var fixture = new ManagedFixture();
        for (int status : List.of(401, 403, 404, 302, 503)) {
            var count = new java.util.concurrent.atomic.AtomicInteger();
            var client = fixture.client("yaoguang", fixture.routes(), (uri, service, user, timeout) -> {
                count.incrementAndGet(); return new HttpRbac3AuthorizationClient.HttpResponse(status, "{}");
            });
            assertThatThrownBy(() -> client.fetch("yaoguang", fixture.user(), "user-at"))
                    .isInstanceOf(status <= 404 && status != 302 ? Rbac3AuthorizationClient.AuthorizationDeniedException.class
                            : Rbac3AuthorizationClient.AuthorizationUnavailableException.class);
            assertThat(count).hasValue(1);
        }
        var client = fixture.client("yaoguang", fixture.routes(), (uri, service, user, timeout) -> {
            throw new java.io.IOException("private: user-at managed-service-at internal-host");
        });
        assertThatThrownBy(() -> client.fetch("yaoguang", fixture.user(), "user-at"))
                .isInstanceOf(Rbac3AuthorizationClient.AuthorizationUnavailableException.class).hasCause(null)
                .hasMessage("TIANQUAN_JIANSHEN_AUTHORIZATION_UNAVAILABLE");
    }

    @Test void managedTokenAcquisitionAndSendShareOneDeadlineAndCannotSendAfterItExpires() {
        var fixture = new ManagedFixture(); var sends = new java.util.concurrent.atomic.AtomicInteger();
        org.mockito.Mockito.doAnswer(call -> {
            Thread.sleep(150);
            return new org.springframework.security.oauth2.core.OAuth2AccessToken(org.springframework.security.oauth2.core.OAuth2AccessToken.TokenType.BEARER,
                    "managed-service-at", Instant.now(), Instant.now().plusSeconds(60), MANAGED_SCOPES);
        }).when(fixture.oauth).authorizeBounded(org.mockito.ArgumentMatchers.any(), org.mockito.ArgumentMatchers.anyString(), org.mockito.ArgumentMatchers.any());
        var client = new HttpRbac3AuthorizationClient(MANAGED_ENDPOINT, fixture.supplier, Duration.ofMillis(100), objectMapper(),
                "yaoguang", fixture.routes(), (uri, token, user, budget) -> { sends.incrementAndGet(); return new HttpRbac3AuthorizationClient.HttpResponse(200, "{}"); });
        assertThatThrownBy(() -> client.fetch("yaoguang", fixture.user(), "user-at"))
                .isInstanceOf(Rbac3AuthorizationClient.AuthorizationUnavailableException.class);
        assertThat(sends).hasValue(0);
    }

    @Test void actualOwnedJdkTransportUsesNoProxyAndNeverFollowsCredentialRedirects() throws Exception {
        var target = com.sun.net.httpserver.HttpServer.create(new java.net.InetSocketAddress("127.0.0.1", 0), 0);
        var redirect = com.sun.net.httpserver.HttpServer.create(new java.net.InetSocketAddress("127.0.0.1", 0), 0);
        var leaks = new java.util.concurrent.atomic.AtomicInteger();
        target.createContext("/", exchange -> { leaks.incrementAndGet(); exchange.sendResponseHeaders(200, -1); exchange.close(); });
        redirect.createContext("/", exchange -> { exchange.getResponseHeaders().add("Location", "http://127.0.0.1:" + target.getAddress().getPort() + "/leak"); exchange.sendResponseHeaders(302, -1); exchange.close(); });
        target.start(); redirect.start();
        try {
            var client = new HttpRbac3AuthorizationClient(URI.create("http://127.0.0.1:" + redirect.getAddress().getPort()),
                    supplier(ignored -> "service-at"), Duration.ofSeconds(1), objectMapper());
            var field = HttpRbac3AuthorizationClient.class.getDeclaredField("transport"); field.setAccessible(true);
            var transport = field.get(client); var httpField = transport.getClass().getDeclaredField("client"); httpField.setAccessible(true);
            var http = (java.net.http.HttpClient) httpField.get(transport);
            assertThat(http.proxy()).contains(java.net.http.HttpClient.Builder.NO_PROXY);
            assertThat(http.followRedirects()).isEqualTo(java.net.http.HttpClient.Redirect.NEVER);
            assertThat(http.authenticator()).isEmpty(); assertThat(http.cookieHandler()).isEmpty();
            assertThatThrownBy(() -> client.fetch("finance", principal(), "original-user-at"))
                    .isInstanceOf(Rbac3AuthorizationClient.AuthorizationUnavailableException.class);
            assertThat(leaks).hasValue(0); http.shutdownNow();
        } finally { redirect.stop(0); target.stop(0); }
    }

    private final class ManagedFixture {
        final top.egon.cola.platform.tianquan.shoubing.starter.client.IdpServiceOAuth2Client oauth = org.mockito.Mockito.mock(
                top.egon.cola.platform.tianquan.shoubing.starter.client.IdpServiceOAuth2Client.class);
        final top.egon.cola.platform.tianquan.shoubing.starter.autoconfigure.IdpStarterProperties properties = new top.egon.cola.platform.tianquan.shoubing.starter.autoconfigure.IdpStarterProperties();
        final HttpTenantServiceTokenSupplier supplier;
        ManagedFixture() {
            var config = properties.getServiceClient(); config.setAppId("yaoguang-app"); config.setRegistrationId("yaoguang-auth");
            config.setCredentialVersions(Map.of("yaoguang-auth", 1L)); config.setTenantRegistrationIds(Map.of("20", "yaoguang-auth"));
            org.mockito.Mockito.when(oauth.authorizationKey(org.mockito.ArgumentMatchers.any())).thenAnswer(call ->
                    top.egon.cola.platform.tianquan.shoubing.starter.client.ServiceAuthorizationKey.from(call.getArgument(0), MANAGED_ISSUER.toString(), "yaoguang-client", 1L));
            org.mockito.Mockito.when(oauth.authorizeBounded(org.mockito.ArgumentMatchers.any(), org.mockito.ArgumentMatchers.anyString(), org.mockito.ArgumentMatchers.any())).thenReturn(
                    new org.springframework.security.oauth2.core.OAuth2AccessToken(org.springframework.security.oauth2.core.OAuth2AccessToken.TokenType.BEARER,
                            "managed-service-at", Instant.now(), Instant.now().plusSeconds(60), MANAGED_SCOPES));
            supplier = new HttpTenantServiceTokenSupplier(oauth, properties, MANAGED_RESOURCE, MANAGED_SCOPES);
        }
        HttpRbac3AuthorizationClient client(String code, top.egon.cola.platform.tianquan.shoubing.starter.client.IdpTransportBindingRegistry routes,
                HttpRbac3AuthorizationClient.Transport transport) {
            return new HttpRbac3AuthorizationClient(MANAGED_ENDPOINT, supplier, Duration.ofSeconds(1), objectMapper(), code, routes, transport);
        }
        top.egon.cola.platform.tianquan.shoubing.starter.client.IdpTransportBindingRegistry routes() {
            return new top.egon.cola.platform.tianquan.shoubing.starter.client.IdpTransportBindingRegistry(List.of(
                    route("snap", SNAPSHOT_PATH, MANAGED_ISSUER, MANAGED_RESOURCE, "yaoguang-auth", "GET"),
                    route("policy", POLICY_PATH, MANAGED_ISSUER, MANAGED_RESOURCE, "yaoguang-auth", "GET")));
        }
        top.egon.cola.platform.tianquan.shoubing.starter.client.IdpTransportBindingVO route(String id, String path, URI issuer, URI resource, String registration, String method) {
            return new top.egon.cola.platform.tianquan.shoubing.starter.client.IdpTransportBindingVO(id, 7L, issuer, MANAGED_ENDPOINT.resolve(path), resource,
                    registration, top.egon.cola.platform.tianquan.shoubing.starter.client.IdpTransportBindingVO.Operation.RESOURCE, method,
                    path, "auth-system", "jianshen", 8080, top.egon.cola.platform.tianquan.shoubing.starter.client.IdpTransportBindingVO.Transport.HTTP);
        }
        IdentityPrincipal user() { return new IdentityPrincipal("alice", "20", "at-1", Set.of("yaoguang"), Instant.now(), Instant.now().plusSeconds(300), AuthenticationContext.password()); }
        top.egon.cola.platform.tianquan.shoubing.contract.ServiceIdentityPrincipal service() {
            return new top.egon.cola.platform.tianquan.shoubing.contract.ServiceIdentityPrincipal("caller", "20", "caller", "at-2", MANAGED_RESOURCE,
                    1L, MANAGED_SCOPES, "xingyuan", "yaoguang", "test", "credential-1", Instant.now(), Instant.now().plusSeconds(60),
                    "yaoguang-app", top.egon.cola.platform.tianquan.shoubing.contract.ServiceTokenContext.TENANT);
        }
        top.egon.cola.platform.tianquan.jianshen.contract.authorization.RuntimePolicyBinding policyBinding() {
            return new top.egon.cola.platform.tianquan.jianshen.contract.authorization.RuntimePolicyBinding("yaoguang-java", "1", "a".repeat(64), "b".repeat(64), "c".repeat(64));
        }
        top.egon.cola.platform.tianquan.jianshen.contract.permission.CatalogScope scope(String code) {
            return new top.egon.cola.platform.tianquan.jianshen.contract.permission.CatalogScope("10", "20", "xingyuan", code, "default", "test");
        }
        String policyBody(String code) throws java.io.IOException {
            return objectMapper().writeValueAsString(Map.of("data", new top.egon.cola.platform.tianquan.jianshen.contract.authorization.ServicePolicySnapshot(
                    scope(code), "1", "1", policyBinding(), Set.of("yaoguang.read"), Instant.now().plusSeconds(60))));
        }
        String snapshotBody(String code) throws java.io.IOException {
            var now = Instant.now();
            var view = new top.egon.cola.platform.tianquan.jianshen.contract.permission.EffectivePermissionSnapshot(
                    MANAGED_ISSUER.toString(), "alice", scope(code), "1", "2", "3",
                    new top.egon.cola.platform.tianquan.jianshen.contract.permission.EffectivePermissionSnapshot.ActiveRoleContext(code, List.of("7"), List.of("7")),
                    List.of("knowledge:read"), now.plusSeconds(60));
            var snapshot = new top.egon.cola.platform.tianquan.jianshen.contract.authorization.SystemAuthorizationSnapshot("20", "alice", "30", code,
                    2, 3, List.of("7"), null, null, Set.of("knowledge:read"), Set.of(), Map.of(), Map.of(), "checksum", now, view.snapshotExpiresAt(), view, policyBinding());
            return objectMapper().writeValueAsString(Map.of("data", snapshot));
        }
    }

    private HttpRbac3AuthorizationClient client(
            HttpRbac3AuthorizationClient.Transport transport) {
        return new HttpRbac3AuthorizationClient(
                URI.create("http://127.0.0.1:8088"), supplier(ignored -> "service-token"),
                Duration.ofSeconds(1), objectMapper(), transport);
    }

    private HttpTenantServiceTokenSupplier supplier(
            java.util.function.Function<String, String> value) {
        return new HttpTenantServiceTokenSupplier(
                "tianquan-jianshen-client", () -> value.apply("tenant-a"),
                URI.create("https://tianquan-jianshen.example/internal"),
                Set.of("tianquan-jianshen:authorization:read"), Duration.ofSeconds(5),
                Clock.systemUTC(), request ->
                new HttpTenantServiceTokenSupplier.TokenResponse(
                        value.apply(request.tenantId()), "Bearer", 300));
    }

    private ObjectMapper objectMapper() {
        return new ObjectMapper().registerModule(new JavaTimeModule());
    }

    private void setVerifiedUserToken(String token) {
        MockHttpServletRequest request = new MockHttpServletRequest();
        VerifiedUserTokenCarrier.set(request, token);
        RequestContextHolder.setRequestAttributes(new ServletRequestAttributes(request));
    }

    private IdentityPrincipal principal() {
        return new IdentityPrincipal(
                "alice-sub", "tenant-a", "token-1", Set.of("finance"),
                Instant.parse("2026-08-02T04:59:30Z"),
                Instant.parse("2026-08-02T06:00:00Z"),
                AuthenticationContext.password());
    }

    private String responseBody() {
        return """
                {"data":{"tenantId":"tenant-a","identitySub":"alice-sub",
                "rbac3UserId":"101","systemCode":"finance",
                "authVersion":7,"policyVersion":11,
                "activeRoleIds":["role-1"],"permissions":["payment:read"],
                "resourceCodes":[],
                "dataScopes":{},"fieldPolicies":{},"checksum":"sha256:alice-sub",
                "generatedAt":"2026-08-02T05:00:00Z",
                "expiresAt":"2026-08-02T06:00:00Z"}}
                """;
    }
}
