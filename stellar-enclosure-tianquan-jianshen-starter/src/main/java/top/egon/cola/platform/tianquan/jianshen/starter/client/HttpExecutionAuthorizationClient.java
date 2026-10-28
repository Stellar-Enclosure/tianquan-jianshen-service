package top.egon.cola.platform.tianquan.jianshen.starter.client;

import com.fasterxml.jackson.core.JsonParser;
import com.fasterxml.jackson.databind.DeserializationFeature;
import com.fasterxml.jackson.databind.MapperFeature;
import com.fasterxml.jackson.databind.ObjectMapper;
import java.net.URI;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.nio.ByteBuffer;
import java.time.Clock;
import java.time.Duration;
import java.time.Instant;
import java.util.Arrays;
import java.util.List;
import java.util.Map;
import java.util.Objects;
import java.util.Set;
import java.util.concurrent.CompletableFuture;
import java.util.concurrent.CompletionStage;
import java.util.concurrent.ExecutionException;
import java.util.concurrent.Flow;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.TimeoutException;
import org.springframework.http.MediaType;
import top.egon.cola.platform.tianquan.jianshen.contract.authorization.ExecutionAuthorizationContract;
import top.egon.cola.platform.tianquan.shoubing.contract.ServiceTokenContext;
import top.egon.cola.platform.tianquan.shoubing.starter.client.IdpServiceOAuth2Client;
import top.egon.cola.platform.tianquan.shoubing.starter.client.IdpServiceTokenRequest;

/** A single issuer/tenant/SERVICE binding for deferred execution authorization. */
public final class HttpExecutionAuthorizationClient {
    private static final int MAX_RESPONSE = 64 * 1024;
    private final URI baseUri;
    private final URI issuer;
    private final String tenantId;
    private final IdpServiceTokenRequest service;
    private final IdpServiceOAuth2Client oauth;
    private final HttpClient http;
    private final ObjectMapper mapper;
    private final Duration timeout;
    private final Clock clock;

    public HttpExecutionAuthorizationClient(URI baseUri, URI issuer, IdpServiceTokenRequest service,
            IdpServiceOAuth2Client oauth, ObjectMapper mapper, Duration timeout) {
        this(baseUri, issuer, service, oauth, mapper, timeout,
                HttpClient.newBuilder().connectTimeout(requireTimeout(timeout)).followRedirects(HttpClient.Redirect.NEVER).build(), Clock.systemUTC());
    }

    HttpExecutionAuthorizationClient(URI baseUri, URI issuer, IdpServiceTokenRequest service,
            IdpServiceOAuth2Client oauth, ObjectMapper mapper, Duration timeout, HttpClient http, Clock clock) {
        URI base = secureUri(baseUri);
        this.baseUri = URI.create(base.toASCIIString().replaceAll("/+$", "") + "/");
        this.issuer = secureUri(issuer);
        this.service = Objects.requireNonNull(service, "service");
        this.oauth = Objects.requireNonNull(oauth, "oauth");
        this.mapper = Objects.requireNonNull(mapper, "mapper").copy().enable(JsonParser.Feature.STRICT_DUPLICATE_DETECTION)
                .enable(DeserializationFeature.FAIL_ON_UNKNOWN_PROPERTIES, DeserializationFeature.FAIL_ON_TRAILING_TOKENS,
                        DeserializationFeature.FAIL_ON_MISSING_CREATOR_PROPERTIES, DeserializationFeature.FAIL_ON_NULL_CREATOR_PROPERTIES,
                        DeserializationFeature.FAIL_ON_NULL_FOR_PRIMITIVES, DeserializationFeature.USE_BIG_DECIMAL_FOR_FLOATS)
                .disable(MapperFeature.ALLOW_COERCION_OF_SCALARS);
        this.timeout = requireTimeout(timeout);
        this.http = Objects.requireNonNull(http, "http"); this.clock = Objects.requireNonNull(clock, "clock");
        if (http.followRedirects() != HttpClient.Redirect.NEVER || service.context() != ServiceTokenContext.TENANT
                || service.tenantId() == null || !service.tenantId().matches("[1-9][0-9]{0,18}")
                || !service.scopes().contains(ExecutionAuthorizationContract.SERVICE_SCOPE)) {
            throw new IllegalArgumentException("EXECUTION_AUTHORIZATION_CLIENT_BINDING_INVALID");
        }
        try { Long.parseLong(service.tenantId()); }
        catch (NumberFormatException invalid) { throw new IllegalArgumentException("EXECUTION_AUTHORIZATION_CLIENT_BINDING_INVALID"); }
        tenantId = service.tenantId();
        requireIssuer(service);
    }

    /** Compares the authority decision with the caller's immutable local execution intent. */
    public ExecutionAuthorizationContract.Decision decide(ExecutionAuthorizationContract.Request request, Expectation expected) {
        Objects.requireNonNull(request, "request"); Objects.requireNonNull(expected, "expected");
        if (!issuer.equals(expected.issuer()) || !tenantId.equals(expected.tenantId())) throw unavailable();
        var context = new IdpServiceTokenRequest(service.registrationId(), service.appId(), service.audience(),
                service.context(), service.tenantId(), Set.of(ExecutionAuthorizationContract.SERVICE_SCOPE));
        long started = System.nanoTime();
        String token;
        try { token = oauth.authorizeBounded(context, issuer.toASCIIString(), timeout).getTokenValue(); }
        catch (RuntimeException failed) { throw unavailable(); }
        if (token == null || token.length() > 16_384 || !token.matches("[A-Za-z0-9._~+/-]+=*")) throw unavailable();
        byte[] payload;
        try { payload = mapper.writeValueAsBytes(request); }
        catch (com.fasterxml.jackson.core.JsonProcessingException | RuntimeException invalid) { throw unavailable(); }
        if (payload.length > ExecutionAuthorizationContract.MAX_REQUEST_BYTES) {
            Arrays.fill(payload, (byte) 0); throw unavailable();
        }
        CompletableFuture<HttpResponse<byte[]>> pending = null;
        byte[] body = null;
        try {
            var builder = HttpRequest.newBuilder(baseUri.resolve(ExecutionAuthorizationContract.PATH.substring(1))).timeout(Duration.ofNanos(remaining(started)))
                    .header("Authorization", "Bearer " + token).header("Content-Type", "application/json")
                    .header("Accept", "application/json").header("Cache-Control", "no-store");
            var trace = top.egon.cola.component.common.trace.TraceContext.capture();
            if (trace.traceId() != null) trace.child().inject(builder::header);
            var httpRequest = builder.POST(HttpRequest.BodyPublishers.ofByteArray(payload)).build();
            pending = http.sendAsync(httpRequest, info -> new BoundedBody(MAX_RESPONSE));
            var response = pending.get(remaining(started), TimeUnit.NANOSECONDS);
            body = response.body(); if (body == null) throw unavailable();
            if (response.statusCode() == 401) {
                oauth.invalidateBounded(context, issuer.toASCIIString(), Duration.ofNanos(remaining(started)));
                throw unavailable();
            }
            if (response.statusCode() == 403 && json(response) && denied(body)) throw new ExecutionAuthorizationDeniedException();
            if (response.statusCode() != 200 || !json(response) || body.length == 0) throw unavailable();
            ExecutionAuthorizationContract.Decision decision;
            try {
                var node = mapper.readTree(body);
                if (node == null || !node.isObject() || !textual(node, "grantId", "issuer", "tenantId", "subject", "resource", "purpose", "intentId", "bindingSha256")
                        || !node.path("sessionRequired").isBoolean() || !node.path("authVersion").isIntegralNumber()
                        || !node.path("policyVersion").isIntegralNumber() || !instant(node.path("deadlineAt")) || !instant(node.path("expiresAt"))) throw unavailable();
                decision = mapper.treeToValue(node, ExecutionAuthorizationContract.Decision.class);
            } catch (java.io.IOException | IllegalArgumentException invalid) { throw unavailable(); }
            if (decision == null || !request.grantId().equals(decision.grantId())
                    || !expected.issuer().toASCIIString().equals(decision.issuer()) || !expected.tenantId().equals(decision.tenantId())
                    || !expected.subject().equals(decision.subject()) || !expected.resource().toASCIIString().equals(decision.resource())
                    || !expected.purpose().equals(decision.purpose()) || !expected.intentId().equals(decision.intentId())
                    || !expected.bindingSha256().equals(decision.bindingSha256()) || expected.sessionRequired() != decision.sessionRequired()
                    || !expected.deadlineAt().equals(decision.deadlineAt()) || !decision.expiresAt().isAfter(clock.instant())
                    || decision.expiresAt().isAfter(expected.deadlineAt())) throw unavailable();
            return decision;
        } catch (ExecutionAuthorizationDeniedException | ExecutionAuthorizationUnavailableException failure) {
            throw failure;
        } catch (InterruptedException interrupted) {
            if (pending != null) pending.cancel(true); Thread.currentThread().interrupt(); throw unavailable();
        } catch (TimeoutException expired) {
            if (pending != null) pending.cancel(true); throw unavailable();
        } catch (ExecutionException | RuntimeException failure) {
            throw unavailable();
        } finally {
            if (pending != null && !pending.isDone()) pending.cancel(true);
            Arrays.fill(payload, (byte) 0); if (body != null) Arrays.fill(body, (byte) 0);
        }
    }

    private long remaining(long started) {
        long elapsed = Math.max(0L, System.nanoTime() - started);
        long value = timeout.toNanos() - elapsed;
        if (value <= 0) throw unavailable();
        return value;
    }

    private static boolean textual(com.fasterxml.jackson.databind.JsonNode node, String... names) {
        for (String name : names) if (!node.path(name).isTextual()) return false;
        return true;
    }

    private static boolean instant(com.fasterxml.jackson.databind.JsonNode value) {
        return value.isTextual() || value.isNumber();
    }

    private boolean denied(byte[] body) {
        try { Map<?, ?> value = mapper.readValue(body, Map.class); return value.size() == 1 && "access_denied".equals(value.get("error")); }
        catch (java.io.IOException | RuntimeException invalid) { return false; }
    }

    private static boolean json(HttpResponse<?> response) {
        try {
            var values = response.headers().allValues("Content-Type");
            return values.size() == 1 && MediaType.APPLICATION_JSON.isCompatibleWith(MediaType.parseMediaType(values.getFirst()));
        } catch (IllegalArgumentException invalid) { return false; }
    }

    private void requireIssuer(IdpServiceTokenRequest context) {
        try { if (!issuer.toASCIIString().equals(oauth.authorizationKey(context).issuer())) throw unavailable(); }
        catch (ExecutionAuthorizationUnavailableException failure) { throw failure; }
        catch (RuntimeException invalid) { throw unavailable(); }
    }

    private static URI secureUri(URI value) {
        if (value == null || !"https".equalsIgnoreCase(value.getScheme()) || value.getHost() == null
                || value.getUserInfo() != null || value.getQuery() != null || value.getFragment() != null
                || !value.normalize().equals(value) || value.toASCIIString().length() > 2048) {
            throw new IllegalArgumentException("EXECUTION_AUTHORIZATION_CLIENT_URI_INVALID");
        }
        return value;
    }

    private static Duration requireTimeout(Duration value) {
        if (value == null || value.isZero() || value.isNegative() || value.compareTo(Duration.ofSeconds(5)) > 0) {
            throw new IllegalArgumentException("EXECUTION_AUTHORIZATION_CLIENT_TIMEOUT_INVALID");
        }
        return value;
    }

    /** Trusted expectation from the local ledger, never from the remote response. */
    public record Expectation(URI issuer, String tenantId, String subject, URI resource, String purpose, String intentId,
                              String bindingSha256, boolean sessionRequired, Instant deadlineAt) {
        public Expectation {
            issuer = secureUri(issuer); resource = secureUri(resource);
            if (tenantId == null || !tenantId.matches("[1-9][0-9]{0,18}") || subject == null || subject.isBlank()
                    || !subject.equals(subject.trim()) || subject.length() > 256 || subject.chars().anyMatch(Character::isISOControl) || purpose == null
                    || !purpose.matches("[A-Z][A-Z0-9_]{0,95}") || intentId == null || intentId.length() != 36
                    || bindingSha256 == null || !bindingSha256.matches("[0-9a-f]{64}") || deadlineAt == null) {
                throw new IllegalArgumentException("EXECUTION_AUTHORIZATION_EXPECTATION_INVALID");
            }
            try {
                Long.parseLong(tenantId);
                if (!java.util.UUID.fromString(intentId).toString().equals(intentId)) throw new IllegalArgumentException();
            } catch (IllegalArgumentException invalid) { throw new IllegalArgumentException("EXECUTION_AUTHORIZATION_EXPECTATION_INVALID"); }
        }
        @Override public String toString() { return "ExecutionAuthorizationExpectation[redacted]"; }
    }

    private static ExecutionAuthorizationUnavailableException unavailable() { return new ExecutionAuthorizationUnavailableException(); }
    public static final class ExecutionAuthorizationDeniedException extends RuntimeException {
        public ExecutionAuthorizationDeniedException() { super("EXECUTION_AUTHORIZATION_DENIED"); }
    }
    public static final class ExecutionAuthorizationUnavailableException extends RuntimeException {
        public ExecutionAuthorizationUnavailableException() { super("EXECUTION_AUTHORIZATION_UNAVAILABLE"); }
    }

    private static final class BoundedBody implements HttpResponse.BodySubscriber<byte[]> {
        private final byte[] buffer;
        private final CompletableFuture<byte[]> result = new CompletableFuture<>();
        private Flow.Subscription subscription;
        private int size;
        private BoundedBody(int limit) { buffer = new byte[limit]; }
        @Override public CompletionStage<byte[]> getBody() { return result; }
        @Override public void onSubscribe(Flow.Subscription value) {
            if (subscription != null) { value.cancel(); return; } subscription = value; value.request(1);
        }
        @Override public void onNext(List<ByteBuffer> values) {
            for (ByteBuffer value : values) {
                int count = value.remaining();
                if (count > buffer.length - size) {
                    subscription.cancel(); Arrays.fill(buffer, (byte) 0);
                    result.completeExceptionally(new IllegalStateException("EXECUTION_AUTHORIZATION_RESPONSE_TOO_LARGE")); return;
                }
                value.get(buffer, size, count); size += count;
            }
            subscription.request(1);
        }
        @Override public void onError(Throwable failure) { Arrays.fill(buffer, (byte) 0); result.completeExceptionally(failure); }
        @Override public void onComplete() { byte[] bytes = Arrays.copyOf(buffer, size); Arrays.fill(buffer, (byte) 0); result.complete(bytes); }
    }
}
