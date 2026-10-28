package top.egon.cola.platform.tianquan.jianshen.starter.client;

import com.fasterxml.jackson.databind.ObjectMapper;
import java.io.ByteArrayOutputStream;
import java.net.URI;
import java.net.http.HttpClient;
import java.net.http.HttpHeaders;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.nio.ByteBuffer;
import java.time.Clock;
import java.time.Duration;
import java.time.Instant;
import java.time.ZoneOffset;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.concurrent.CompletableFuture;
import java.util.concurrent.Flow;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.Test;
import org.springframework.http.MediaType;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.oauth2.core.OAuth2AccessToken;
import org.springframework.security.web.method.annotation.AuthenticationPrincipalArgumentResolver;
import org.springframework.test.web.servlet.setup.MockMvcBuilders;
import top.egon.cola.platform.tianquan.jianshen.admin.authorization.runtime.catalog.ExecutionGrantAuthorizationController;
import top.egon.cola.platform.tianquan.jianshen.admin.authorization.runtime.catalog.ExecutionGrantAuthorizationService;
import top.egon.cola.platform.tianquan.jianshen.contract.authorization.ExecutionAuthorizationContract;
import top.egon.cola.platform.tianquan.jianshen.core.rule.Rbac3RuleViolation;
import top.egon.cola.platform.tianquan.shoubing.contract.ServiceIdentityPrincipal;
import top.egon.cola.platform.tianquan.shoubing.contract.ServiceTokenContext;
import top.egon.cola.platform.tianquan.shoubing.starter.client.IdpServiceOAuth2Client;
import top.egon.cola.platform.tianquan.shoubing.starter.client.IdpServiceTokenRequest;
import top.egon.cola.platform.tianquan.shoubing.starter.client.ServiceAuthorizationKey;
import top.egon.cola.platform.tianquan.shoubing.starter.security.IdpAuthenticationToken;

import static org.junit.jupiter.api.Assertions.*;
import static org.mockito.ArgumentMatchers.*;
import static org.mockito.Mockito.*;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.post;

/** Exercises the client and MVC contract without opening a network listener. */
class ExecutionAuthorizationClientServerContractTest {
    @AfterEach void clear() { SecurityContextHolder.clearContext(); }

    @Test void client_consumes_scoped_decision_and_keeps_service_failures_distinct() throws Exception {
        Instant now = Instant.parse("2026-10-29T00:00:00Z"); URI issuer = URI.create("https://idp.example/tenants/101");
        URI resource = URI.create("https://api.example/tianji"); String id = "9" + "1".repeat(62);
        String intent = "00000000-0000-0000-0000-000000000123";
        var request = new ExecutionAuthorizationContract.Request("tianji", id, "ENC:v1:key:nonce:fixture");
        var decision = new ExecutionAuthorizationContract.Decision(id, issuer.toString(), "101", "alice", resource.toString(),
                "TEST_RUN", intent, "c".repeat(64), true, now.plusSeconds(600), now.plusSeconds(30), 2, 3);
        var expected = new HttpExecutionAuthorizationClient.Expectation(issuer, "101", "alice", resource, "TEST_RUN", intent,
                "c".repeat(64), true, now.plusSeconds(600));
        var principal = new ServiceIdentityPrincipal("agent", "101", "agent", "123", URI.create("https://api.example/rbac"), 1,
                Set.of(ExecutionAuthorizationContract.SERVICE_SCOPE), "platform", "tianji", "test", "credential",
                now.minusSeconds(1), now.plusSeconds(300), "agent", ServiceTokenContext.TENANT);
        SecurityContextHolder.getContext().setAuthentication(new IdpAuthenticationToken(principal, List.of(), issuer));
        var service = mock(ExecutionGrantAuthorizationService.class);
        when(service.decide(principal, issuer, request)).thenReturn(decision)
                .thenThrow(new Rbac3RuleViolation("EXECUTION_GRANT_DENIED"))
                .thenThrow(new Rbac3RuleViolation("APPLICATION_BINDING_DENIED"));
        var mapper = new ObjectMapper().findAndRegisterModules();
        var mvc = MockMvcBuilders.standaloneSetup(new ExecutionGrantAuthorizationController(service, mapper))
                .setCustomArgumentResolvers(new AuthenticationPrincipalArgumentResolver()).build();
        var oauth = mock(IdpServiceOAuth2Client.class);
        var context = new IdpServiceTokenRequest("registration", "agent", URI.create("https://api.example/rbac"), ServiceTokenContext.TENANT,
                "101", Set.of(ExecutionAuthorizationContract.SERVICE_SCOPE));
        when(oauth.authorizationKey(any())).thenAnswer(inv -> {
            IdpServiceTokenRequest value = inv.getArgument(0);
            return new ServiceAuthorizationKey(issuer.toString(), value.registrationId(), "agent", 1, value.appId(),
                    value.audience(), value.context(), value.tenantId(), value.scopes());
        });
        when(oauth.authorize(any())).thenReturn(new OAuth2AccessToken(OAuth2AccessToken.TokenType.BEARER, "service-proof", now, now.plusSeconds(300)));
        var http = mock(HttpClient.class); when(http.followRedirects()).thenReturn(HttpClient.Redirect.NEVER);
        when(http.<byte[]>sendAsync(any(), any())).thenAnswer(inv -> {
            HttpRequest outbound = inv.getArgument(0); HttpResponse.BodyHandler<byte[]> handler = inv.getArgument(1);
            var actual = mvc.perform(post(outbound.uri().getRawPath()).contentType(MediaType.APPLICATION_JSON)
                    .header("Authorization", outbound.headers().firstValue("Authorization").orElseThrow()).content(readBody(outbound)))
                    .andReturn().getResponse();
            @SuppressWarnings("unchecked") HttpResponse<byte[]> response = mock(HttpResponse.class);
            when(response.statusCode()).thenReturn(actual.getStatus());
            String type = actual.getContentType();
            when(response.headers()).thenReturn(HttpHeaders.of(type == null ? Map.of() : Map.of("Content-Type", List.of(type)), (a, b) -> true));
            var info = mock(HttpResponse.ResponseInfo.class); when(info.statusCode()).thenReturn(actual.getStatus());
            var subscriber = handler.apply(info);
            subscriber.onSubscribe(new Flow.Subscription() { public void request(long n) { } public void cancel() { } });
            subscriber.onNext(List.of(ByteBuffer.wrap(actual.getContentAsByteArray()))); subscriber.onComplete();
            return subscriber.getBody().thenApply(bytes -> { when(response.body()).thenReturn(bytes); return response; }).toCompletableFuture();
        });
        var client = new HttpExecutionAuthorizationClient(URI.create("https://rbac.example"), issuer, context, oauth, mapper,
                Duration.ofSeconds(1), http, Clock.fixed(now, ZoneOffset.UTC));
        assertEquals(decision, client.decide(request, expected));
        assertThrows(HttpExecutionAuthorizationClient.ExecutionAuthorizationDeniedException.class, () -> client.decide(request, expected));
        assertThrows(HttpExecutionAuthorizationClient.ExecutionAuthorizationUnavailableException.class, () -> client.decide(request, expected));
        verify(service, times(3)).decide(principal, issuer, request);
    }

    private static byte[] readBody(HttpRequest request) {
        var result = new CompletableFuture<byte[]>(); var output = new ByteArrayOutputStream();
        request.bodyPublisher().orElseThrow().subscribe(new Flow.Subscriber<>() {
            public void onSubscribe(Flow.Subscription subscription) { subscription.request(Long.MAX_VALUE); }
            public void onNext(ByteBuffer value) { byte[] bytes = new byte[value.remaining()]; value.get(bytes); output.writeBytes(bytes); }
            public void onError(Throwable error) { result.completeExceptionally(error); }
            public void onComplete() { result.complete(output.toByteArray()); }
        });
        return result.join();
    }
}
