package top.egon.cola.platform.tianquan.jianshen.starter.client;

import com.fasterxml.jackson.databind.ObjectMapper;
import java.io.ByteArrayOutputStream;
import java.net.URI;
import java.net.http.HttpClient;
import java.net.http.HttpHeaders;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.nio.ByteBuffer;
import java.nio.charset.StandardCharsets;
import java.time.Clock;
import java.time.Duration;
import java.time.Instant;
import java.time.ZoneOffset;
import java.util.ArrayDeque;
import java.util.ArrayList;
import java.util.List;
import java.util.Map;
import java.util.Queue;
import java.util.Set;
import java.util.concurrent.CompletableFuture;
import java.util.concurrent.Flow;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.springframework.security.oauth2.core.OAuth2AccessToken;
import top.egon.cola.platform.tianquan.jianshen.contract.authorization.ExecutionAuthorizationContract;
import top.egon.cola.platform.tianquan.shoubing.contract.ServiceTokenContext;
import top.egon.cola.platform.tianquan.shoubing.starter.client.IdpServiceOAuth2Client;
import top.egon.cola.platform.tianquan.shoubing.starter.client.IdpServiceTokenRequest;
import top.egon.cola.platform.tianquan.shoubing.starter.client.ServiceAuthorizationKey;

import static org.junit.jupiter.api.Assertions.*;
import static org.mockito.ArgumentMatchers.*;
import static org.mockito.Mockito.*;

class HttpExecutionAuthorizationClientTest {
    private static final Instant NOW = Instant.parse("2026-10-29T00:00:00Z");
    private static final URI ISSUER = URI.create("https://idp.example/tenants/101");
    private static final URI RESOURCE = URI.create("https://api.example/tianji");
    private static final URI BASE = URI.create("https://rbac.example/prefix");
    private static final String ID = "9" + "1".repeat(62);
    private static final String SECRET = "ENC:v1:key:nonce:secret-sentinel";
    private static final String INTENT = "00000000-0000-0000-0000-000000000123";
    private final ExecutionAuthorizationContract.Request request = new ExecutionAuthorizationContract.Request("tianji", ID, SECRET);
    private final HttpExecutionAuthorizationClient.Expectation expected = new HttpExecutionAuthorizationClient.Expectation(
            ISSUER, "101", "alice", RESOURCE, "TEST_RUN", INTENT, "c".repeat(64), true, NOW.plusSeconds(600));
    private final ObjectMapper mapper = new ObjectMapper().findAndRegisterModules();
    private final IdpServiceOAuth2Client oauth = mock(IdpServiceOAuth2Client.class);
    private final HttpClient http = mock(HttpClient.class);
    private final Queue<Reply> replies = new ArrayDeque<>();
    private final List<Captured> requests = new ArrayList<>();
    private final IdpServiceTokenRequest service = new IdpServiceTokenRequest("registration", "agent", URI.create("https://api.example/rbac"),
            ServiceTokenContext.TENANT, "101", Set.of(ExecutionAuthorizationContract.SERVICE_SCOPE, "another:scope"));
    private HttpExecutionAuthorizationClient client;

    @BeforeEach void setup() {
        when(http.followRedirects()).thenReturn(HttpClient.Redirect.NEVER);
        when(oauth.authorizationKey(any())).thenAnswer(invocation -> {
            IdpServiceTokenRequest value = invocation.getArgument(0);
            return new ServiceAuthorizationKey(ISSUER.toASCIIString(), value.registrationId(), "agent", 1, value.appId(),
                    value.audience(), value.context(), value.tenantId(), value.scopes());
        });
        when(oauth.authorize(any())).thenReturn(new OAuth2AccessToken(OAuth2AccessToken.TokenType.BEARER,
                "service-proof-sentinel", NOW, NOW.plusSeconds(300)));
        when(http.<byte[]>sendAsync(any(), any())).thenAnswer(invocation -> {
            HttpRequest outbound = invocation.getArgument(0);
            HttpResponse.BodyHandler<byte[]> handler = invocation.getArgument(1);
            requests.add(new Captured(outbound, readBody(outbound)));
            Reply reply = replies.remove();
            var response = response(outbound, reply.status(), reply.contentType());
            var info = mock(HttpResponse.ResponseInfo.class); when(info.statusCode()).thenReturn(reply.status());
            var subscriber = handler.apply(info);
            subscriber.onSubscribe(new Flow.Subscription() { public void request(long n) { } public void cancel() { } });
            if (reply.body().length != 0) subscriber.onNext(List.of(ByteBuffer.wrap(reply.body())));
            subscriber.onComplete();
            return subscriber.getBody().thenApply(bytes -> { when(response.body()).thenReturn(bytes); return response; }).toCompletableFuture();
        });
        client = create(service, ISSUER, http, Duration.ofSeconds(1));
    }

    @Test void sends_scoped_service_request_and_binds_every_decision_field_to_local_expectations() throws Exception {
        var result = decision(ID, ISSUER.toString(), "101", "alice", RESOURCE.toString(), "TEST_RUN", INTENT,
                "c".repeat(64), true, NOW.plusSeconds(600), NOW.plusSeconds(30));
        add(200, mapper.writeValueAsBytes(result));
        assertEquals(result, client.decide(request, expected));
        var sent = requests.getFirst();
        assertEquals("https://rbac.example/prefix/internal/v1/authorization/execution-grants:decide", sent.request().uri().toString());
        assertEquals("Bearer service-proof-sentinel", sent.request().headers().firstValue("Authorization").orElseThrow());
        assertEquals("no-store", sent.request().headers().firstValue("Cache-Control").orElseThrow());
        assertEquals(SECRET, mapper.readTree(sent.body()).get("ciphertext").asText());
        verify(oauth).authorize(argThat(value -> value.scopes().equals(Set.of(ExecutionAuthorizationContract.SERVICE_SCOPE))));
        assertFalse(expected.toString().contains("alice")); assertFalse(request.toString().contains(SECRET));
    }

    @Test void numeric_timestamps_preserve_postgres_microseconds() throws Exception {
        Instant deadline = NOW.plusSeconds(600).plusNanos(123_456_000);
        var preciseExpected = new HttpExecutionAuthorizationClient.Expectation(ISSUER, "101", "alice", RESOURCE,
                "TEST_RUN", INTENT, "c".repeat(64), true, deadline);
        var result = decision(ID, ISSUER.toString(), "101", "alice", RESOURCE.toString(), "TEST_RUN", INTENT,
                "c".repeat(64), true, deadline, NOW.plusSeconds(30).plusNanos(654_321_000));
        add(200, mapper.writeValueAsBytes(result));
        assertEquals(result, client.decide(request, preciseExpected));
    }

    @Test void rejects_any_mismatched_or_expired_attested_identity_and_intent() throws Exception {
        for (var wrong : List.of(
                decision("9" + "2".repeat(62), ISSUER.toString(), "101", "alice", RESOURCE.toString(), "TEST_RUN", INTENT, "c".repeat(64), true, NOW.plusSeconds(600), NOW.plusSeconds(30)),
                decision(ID, "https://other.example/tenant", "101", "alice", RESOURCE.toString(), "TEST_RUN", INTENT, "c".repeat(64), true, NOW.plusSeconds(600), NOW.plusSeconds(30)),
                decision(ID, ISSUER.toString(), "102", "alice", RESOURCE.toString(), "TEST_RUN", INTENT, "c".repeat(64), true, NOW.plusSeconds(600), NOW.plusSeconds(30)),
                decision(ID, ISSUER.toString(), "101", "bob", RESOURCE.toString(), "TEST_RUN", INTENT, "c".repeat(64), true, NOW.plusSeconds(600), NOW.plusSeconds(30)),
                decision(ID, ISSUER.toString(), "101", "alice", "https://foreign.example/tianji", "TEST_RUN", INTENT, "c".repeat(64), true, NOW.plusSeconds(600), NOW.plusSeconds(30)),
                decision(ID, ISSUER.toString(), "101", "alice", RESOURCE.toString(), "OTHER", INTENT, "c".repeat(64), true, NOW.plusSeconds(600), NOW.plusSeconds(30)),
                decision(ID, ISSUER.toString(), "101", "alice", RESOURCE.toString(), "TEST_RUN", "00000000-0000-0000-0000-000000000124", "c".repeat(64), true, NOW.plusSeconds(600), NOW.plusSeconds(30)),
                decision(ID, ISSUER.toString(), "101", "alice", RESOURCE.toString(), "TEST_RUN", INTENT, "d".repeat(64), true, NOW.plusSeconds(600), NOW.plusSeconds(30)),
                decision(ID, ISSUER.toString(), "101", "alice", RESOURCE.toString(), "TEST_RUN", INTENT, "c".repeat(64), false, NOW.plusSeconds(600), NOW.plusSeconds(30)),
                decision(ID, ISSUER.toString(), "101", "alice", RESOURCE.toString(), "TEST_RUN", INTENT, "c".repeat(64), true, NOW.plusSeconds(601), NOW.plusSeconds(30)),
                decision(ID, ISSUER.toString(), "101", "alice", RESOURCE.toString(), "TEST_RUN", INTENT, "c".repeat(64), true, NOW.plusSeconds(600), NOW))) {
            add(200, mapper.writeValueAsBytes(wrong));
            assertThrows(HttpExecutionAuthorizationClient.ExecutionAuthorizationUnavailableException.class, () -> client.decide(request, expected));
        }
    }

    @Test void only_an_explicit_grant_denial_is_denied_and_no_request_is_retried() {
        add(403, "{\"error\":\"access_denied\"}".getBytes(StandardCharsets.UTF_8));
        assertThrows(HttpExecutionAuthorizationClient.ExecutionAuthorizationDeniedException.class, () -> client.decide(request, expected));
        add(403, "{\"error\":\"service_binding_denied\"}".getBytes(StandardCharsets.UTF_8));
        assertThrows(HttpExecutionAuthorizationClient.ExecutionAuthorizationUnavailableException.class, () -> client.decide(request, expected));
        add(401, "{}".getBytes(StandardCharsets.UTF_8));
        assertThrows(HttpExecutionAuthorizationClient.ExecutionAuthorizationUnavailableException.class, () -> client.decide(request, expected));
        verify(oauth).invalidate(argThat(value -> value.scopes().equals(Set.of(ExecutionAuthorizationContract.SERVICE_SCOPE))));
        add(302, new byte[0]);
        assertThrows(HttpExecutionAuthorizationClient.ExecutionAuthorizationUnavailableException.class, () -> client.decide(request, expected));
        assertEquals(4, requests.size());
    }

    @Test void limits_and_strictly_decodes_responses_without_exposing_remote_data() throws Exception {
        add(200, new byte[64 * 1024 + 1]);
        assertThrows(HttpExecutionAuthorizationClient.ExecutionAuthorizationUnavailableException.class, () -> client.decide(request, expected));
        String valid = mapper.writeValueAsString(decision(ID, ISSUER.toString(), "101", "alice", RESOURCE.toString(), "TEST_RUN",
                INTENT, "c".repeat(64), true, NOW.plusSeconds(600), NOW.plusSeconds(30)));
        for (String bad : List.of(valid + "{}", valid.replace("\"grantId\":", "\"grantId\":\"" + ID + "\",\"grantId\":"),
                valid.replace("\"tenantId\":\"101\"", "\"tenantId\":101"), "{\"error\":\"" + SECRET + "\"}")) {
            add(200, bad.getBytes(StandardCharsets.UTF_8));
            var failure = assertThrows(HttpExecutionAuthorizationClient.ExecutionAuthorizationUnavailableException.class, () -> client.decide(request, expected));
            assertFalse(failure.toString().contains(SECRET)); assertNull(failure.getCause());
        }
        replies.add(new Reply(200, valid.getBytes(StandardCharsets.UTF_8), "text/plain"));
        assertThrows(HttpExecutionAuthorizationClient.ExecutionAuthorizationUnavailableException.class, () -> client.decide(request, expected));
    }

    @Test void timeout_cancels_exchange_and_never_replays() {
        var pending = new CompletableFuture<HttpResponse<byte[]>>();
        doReturn(pending).when(http).<byte[]>sendAsync(any(), any());
        var shortClient = create(service, ISSUER, http, Duration.ofMillis(40));
        assertThrows(HttpExecutionAuthorizationClient.ExecutionAuthorizationUnavailableException.class, () -> shortClient.decide(request, expected));
        assertTrue(pending.isCancelled()); verify(http, times(1)).sendAsync(any(), any());
    }

    @Test void unsafe_configuration_or_token_errors_fail_closed_without_credentials() {
        assertThrows(IllegalArgumentException.class, () -> new HttpExecutionAuthorizationClient(URI.create("http://rbac.example"), ISSUER,
                service, oauth, mapper, Duration.ofSeconds(1), http, Clock.fixed(NOW, ZoneOffset.UTC)));
        assertThrows(HttpExecutionAuthorizationClient.ExecutionAuthorizationUnavailableException.class,
                () -> create(service, URI.create("https://other.example/tenant"), http, Duration.ofSeconds(1)));
        when(http.followRedirects()).thenReturn(HttpClient.Redirect.ALWAYS);
        assertThrows(IllegalArgumentException.class, () -> create(service, ISSUER, http, Duration.ofSeconds(1)));
        when(http.followRedirects()).thenReturn(HttpClient.Redirect.NEVER);
        var noScope = new IdpServiceTokenRequest(service.registrationId(), service.appId(), service.audience(), service.context(),
                service.tenantId(), Set.of("other:scope"));
        assertThrows(IllegalArgumentException.class, () -> create(noScope, ISSUER, http, Duration.ofSeconds(1)));
        when(oauth.authorize(any())).thenThrow(new IllegalStateException(SECRET));
        var failure = assertThrows(HttpExecutionAuthorizationClient.ExecutionAuthorizationUnavailableException.class, () -> client.decide(request, expected));
        assertFalse(failure.toString().contains(SECRET)); assertNull(failure.getCause());
    }

    @Test void serializer_failure_and_an_unbound_expectation_never_expose_or_send_a_ticket() {
        var foreign = new HttpExecutionAuthorizationClient.Expectation(URI.create("https://other.example/tenant"), "101", "alice",
                RESOURCE, "TEST_RUN", INTENT, "c".repeat(64), true, NOW.plusSeconds(600));
        assertThrows(HttpExecutionAuthorizationClient.ExecutionAuthorizationUnavailableException.class, () -> client.decide(request, foreign));
        var module = new com.fasterxml.jackson.databind.module.SimpleModule();
        module.addSerializer(ExecutionAuthorizationContract.Request.class, new com.fasterxml.jackson.databind.JsonSerializer<>() {
            @Override public void serialize(ExecutionAuthorizationContract.Request value, com.fasterxml.jackson.core.JsonGenerator generator,
                                            com.fasterxml.jackson.databind.SerializerProvider provider) {
                throw new IllegalStateException(SECRET);
            }
        });
        var unsafe = new ObjectMapper().findAndRegisterModules().registerModule(module);
        var guarded = new HttpExecutionAuthorizationClient(BASE, ISSUER, service, oauth, unsafe, Duration.ofSeconds(1), http,
                Clock.fixed(NOW, ZoneOffset.UTC));
        var failure = assertThrows(HttpExecutionAuthorizationClient.ExecutionAuthorizationUnavailableException.class,
                () -> guarded.decide(request, expected));
        assertFalse(failure.toString().contains(SECRET)); assertNull(failure.getCause());
        verify(http, never()).sendAsync(any(), any());
    }

    private HttpExecutionAuthorizationClient create(IdpServiceTokenRequest value, URI issuer, HttpClient transport, Duration timeout) {
        return new HttpExecutionAuthorizationClient(BASE, issuer, value, oauth, mapper, timeout, transport, Clock.fixed(NOW, ZoneOffset.UTC));
    }
    private void add(int status, byte[] body) { replies.add(new Reply(status, body, "application/json")); }
    private static ExecutionAuthorizationContract.Decision decision(String id, String issuer, String tenant, String subject,
            String resource, String purpose, String intent, String hash, boolean session, Instant deadline, Instant expiry) {
        return new ExecutionAuthorizationContract.Decision(id, issuer, tenant, subject, resource, purpose, intent, hash, session, deadline, expiry, 2, 3);
    }
    @SuppressWarnings("unchecked") private static HttpResponse<byte[]> response(HttpRequest request, int status, String contentType) {
        HttpResponse<byte[]> response = mock(HttpResponse.class); when(response.statusCode()).thenReturn(status);
        when(response.request()).thenReturn(request); when(response.headers()).thenReturn(HttpHeaders.of(Map.of("Content-Type", List.of(contentType)), (a, b) -> true));
        return response;
    }
    private static String readBody(HttpRequest request) {
        var result = new CompletableFuture<String>(); var output = new ByteArrayOutputStream();
        request.bodyPublisher().orElseThrow().subscribe(new Flow.Subscriber<>() {
            public void onSubscribe(Flow.Subscription subscription) { subscription.request(Long.MAX_VALUE); }
            public void onNext(ByteBuffer item) { byte[] bytes = new byte[item.remaining()]; item.get(bytes); output.writeBytes(bytes); }
            public void onError(Throwable error) { result.completeExceptionally(error); }
            public void onComplete() { result.complete(output.toString(StandardCharsets.UTF_8)); }
        });
        return result.join();
    }
    private record Reply(int status, byte[] body, String contentType) { }
    private record Captured(HttpRequest request, String body) { }
}
