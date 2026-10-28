package top.egon.cola.platform.tianquan.jianshen.starter.client;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import top.egon.cola.platform.tianquan.shoubing.contract.IdentityPrincipal;
import top.egon.cola.platform.tianquan.shoubing.starter.security.VerifiedUserTokenCarrier;
import top.egon.cola.platform.tianquan.jianshen.contract.authorization.SystemAuthorizationSnapshot;

import java.io.IOException;
import java.net.URI;
import java.net.URLEncoder;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse.BodyHandlers;
import java.nio.charset.StandardCharsets;
import java.time.Duration;
import java.util.Objects;

/**
 * Fetches USER authorization snapshots with two explicit credentials.
 */
public final class HttpRbac3AuthorizationClient implements Rbac3AuthorizationClient {
    private final URI endpoint;
    private final HttpTenantServiceTokenSupplier serviceTokens;
    private final Duration timeout;
    private final ObjectMapper objectMapper;
    private final Transport transport;

    public HttpRbac3AuthorizationClient(URI endpoint,
                                        HttpTenantServiceTokenSupplier serviceTokens,
                                        Duration timeout,
                                        ObjectMapper objectMapper) {
        this(endpoint, serviceTokens, timeout, objectMapper, new JdkTransport(timeout));
    }

    HttpRbac3AuthorizationClient(URI endpoint,
                                 HttpTenantServiceTokenSupplier serviceTokens,
                                 Duration timeout,
                                 ObjectMapper objectMapper,
                                 Transport transport) {
        this.endpoint = secureEndpoint(endpoint);
        this.serviceTokens = Objects.requireNonNull(serviceTokens, "serviceTokens");
        this.timeout = bounded(timeout);
        this.objectMapper = Objects.requireNonNull(objectMapper, "objectMapper");
        this.transport = Objects.requireNonNull(transport, "transport");
    }

    @Override
    public SystemAuthorizationSnapshot fetch(String systemCode, IdentityPrincipal principal)
            throws InterruptedException {
        Objects.requireNonNull(principal, "principal");
        return fetch(systemCode, principal, VerifiedUserTokenCarrier.current());
    }

    @Override
    public SystemAuthorizationSnapshot fetch(
            String systemCode,
            IdentityPrincipal principal,
            String userAccessToken) throws InterruptedException {
        Objects.requireNonNull(principal, "principal");
        String userToken = requiredUserToken(userAccessToken);
        String serviceToken = serviceTokens.apply(principal.tenantId());
        URI uri = endpoint.resolve("/internal/v1/authorization/snapshots/current?systemCode="
                + encode(systemCode));
        try {
            HttpResponse response = transport.get(uri, serviceToken, userToken, timeout);
            if (response.statusCode() == 401 || response.statusCode() == 403 || response.statusCode() == 404) {
                throw new AuthorizationDeniedException("TIANQUAN_JIANSHEN_AUTHORIZATION_DENIED");
            }
            if (response.statusCode() < 200 || response.statusCode() >= 300) {
                throw new AuthorizationUnavailableException("TIANQUAN_JIANSHEN_AUTHORIZATION_UNAVAILABLE");
            }
            JsonNode data = objectMapper.readTree(response.body()).get("data");
            if (data == null || data.isNull()) {
                throw new AuthorizationUnavailableException("TIANQUAN_JIANSHEN_AUTHORIZATION_RESPONSE_INVALID");
            }
            return objectMapper.treeToValue(data, SystemAuthorizationSnapshot.class);
        } catch (AuthorizationDeniedException | AuthorizationUnavailableException exception) {
            throw exception;
        } catch (IOException | RuntimeException exception) {
            throw new AuthorizationUnavailableException("TIANQUAN_JIANSHEN_AUTHORIZATION_UNAVAILABLE", exception);
        }
    }

    @Override
    public top.egon.cola.platform.tianquan.jianshen.contract.authorization.ServicePolicySnapshot fetchPolicy(String systemCode,
            top.egon.cola.platform.tianquan.shoubing.contract.ServiceIdentityPrincipal caller) throws InterruptedException {
        if (caller == null || caller.tenantId() == null) throw new AuthorizationDeniedException("SERVICE_IDENTITY_DENIED");
        URI uri = endpoint.resolve("/internal/v1/authorization/policies/current?systemCode=" + encode(systemCode));
        try {
            HttpResponse response = transport.get(uri, serviceTokens.apply(caller.tenantId()), null, timeout);
            if (response.statusCode() == 401 || response.statusCode() == 403) throw new AuthorizationDeniedException("SERVICE_POLICY_DENIED");
            if (response.statusCode() != 200) throw new AuthorizationUnavailableException("SERVICE_POLICY_RUNTIME_UNAVAILABLE");
            JsonNode data = objectMapper.readTree(response.body()).get("data");
            if (data == null || data.isNull()) throw new AuthorizationUnavailableException("SERVICE_POLICY_RESPONSE_INVALID");
            var policy = objectMapper.treeToValue(data, top.egon.cola.platform.tianquan.jianshen.contract.authorization.ServicePolicySnapshot.class);
            if (!caller.tenantId().equals(policy.catalogScope().tenantId()) || !systemCode.equals(policy.catalogScope().applicationCode())) {
                throw new AuthorizationDeniedException("SERVICE_POLICY_BINDING_MISMATCH");
            }
            return policy;
        } catch (AuthorizationDeniedException | AuthorizationUnavailableException known) { throw known; }
        catch (IOException | RuntimeException failed) { throw new AuthorizationUnavailableException("SERVICE_POLICY_RUNTIME_UNAVAILABLE", failed); }
    }

    @Override
    public SystemAuthorizationSnapshot fetchDelegated(String systemCode, String verifiedServiceTenant, String userAccessToken)
            throws InterruptedException {
        if (verifiedServiceTenant == null || !verifiedServiceTenant.matches("[1-9][0-9]{0,18}")) {
            throw new AuthorizationDeniedException("DELEGATED_TENANT_INVALID");
        }
        try { Long.parseLong(verifiedServiceTenant); }
        catch (NumberFormatException invalid) { throw new AuthorizationDeniedException("DELEGATED_TENANT_INVALID"); }
        String userToken = requiredUserToken(userAccessToken);
        String serviceToken = serviceTokens.apply(verifiedServiceTenant);
        URI uri = endpoint.resolve("/internal/v1/authorization/snapshots/current?systemCode=" + encode(systemCode));
        try {
            HttpResponse response = transport.get(uri, serviceToken, userToken, timeout);
            if (response.statusCode() == 401 || response.statusCode() == 403 || response.statusCode() == 404) {
                throw new AuthorizationDeniedException("TIANQUAN_JIANSHEN_AUTHORIZATION_DENIED");
            }
            if (response.statusCode() != 200) throw new AuthorizationUnavailableException("TIANQUAN_JIANSHEN_AUTHORIZATION_UNAVAILABLE");
            JsonNode data = objectMapper.readTree(response.body()).get("data");
            if (data == null || data.isNull()) throw new AuthorizationUnavailableException("TIANQUAN_JIANSHEN_AUTHORIZATION_RESPONSE_INVALID");
            var snapshot = objectMapper.treeToValue(data, SystemAuthorizationSnapshot.class);
            var view = snapshot.permissionSnapshot();
            if (view == null || snapshot.policyBinding() == null || !systemCode.equals(snapshot.systemCode())
                    || !verifiedServiceTenant.equals(snapshot.tenantId()) || !view.catalogScope().tenantId().equals(verifiedServiceTenant)
                    || !view.catalogScope().applicationCode().equals(systemCode) || !view.subject().equals(snapshot.identitySub())
                    || !snapshot.expiresAt().isAfter(java.time.Instant.now())) {
                throw new AuthorizationDeniedException("DELEGATED_USER_VIEW_BINDING_MISMATCH");
            }
            return snapshot;
        } catch (AuthorizationDeniedException | AuthorizationUnavailableException known) { throw known; }
        catch (IOException | RuntimeException failed) { throw new AuthorizationUnavailableException("TIANQUAN_JIANSHEN_AUTHORIZATION_UNAVAILABLE", failed); }
    }

    private static String requiredUserToken(String value) {
        if (value == null || value.isBlank() || value.length() > 16_384) {
            throw new AuthorizationUnavailableException(
                    "TIANQUAN_JIANSHEN_USER_TOKEN_UNAVAILABLE"
            );
        }
        return value.trim();
    }

    private static URI secureEndpoint(URI value) {
        Objects.requireNonNull(value, "endpoint");
        boolean loopback = "localhost".equalsIgnoreCase(value.getHost())
                || "127.0.0.1".equals(value.getHost()) || "::1".equals(value.getHost());
        if (!"https".equalsIgnoreCase(value.getScheme())
                && !("http".equalsIgnoreCase(value.getScheme()) && loopback)) {
            throw new IllegalArgumentException("Tianquan-Jianshen authorization endpoint must use HTTPS or loopback HTTP");
        }
        return value;
    }

    private static Duration bounded(Duration value) {
        Objects.requireNonNull(value, "timeout");
        if (value.compareTo(Duration.ofMillis(100)) < 0 || value.compareTo(Duration.ofSeconds(5)) > 0) {
            throw new IllegalArgumentException("timeout is outside the safe range");
        }
        return value;
    }

    private static String encode(String value) {
        if (value == null || value.isBlank()) throw new IllegalArgumentException("systemCode is required");
        return URLEncoder.encode(value, StandardCharsets.UTF_8);
    }

    @FunctionalInterface
    interface Transport {
        HttpResponse get(URI uri, String serviceToken, String userToken, Duration timeout)
                throws IOException, InterruptedException;
    }

    record HttpResponse(int statusCode, String body) {
    }

    static HttpRequest request(URI uri, String serviceToken, String userToken, Duration timeout) {
        HttpRequest.Builder builder = HttpRequest.newBuilder(uri).timeout(timeout)
                .header("Accept", "application/json").header("Authorization", "Bearer " + serviceToken);
        if (userToken != null) builder.header("X-Egon-Subject-Token", userToken);
        var trace = top.egon.cola.component.common.trace.TraceContext.capture();
        if (trace.traceId() != null) trace.child().inject(builder::header);
        return builder.GET().build();
    }

    private static final class JdkTransport implements Transport {
        private final HttpClient client;

        private JdkTransport(Duration timeout) {
            client = HttpClient.newBuilder().connectTimeout(timeout)
                    .followRedirects(HttpClient.Redirect.NEVER).build();
        }

        @Override
        public HttpResponse get(URI uri, String serviceToken, String userToken, Duration timeout)
                throws IOException, InterruptedException {
            var response = client.send(request(uri, serviceToken, userToken, timeout), BodyHandlers.ofString());
            return new HttpResponse(response.statusCode(), response.body());
        }
    }
}
