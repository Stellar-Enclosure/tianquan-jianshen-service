package top.egon.cola.platform.tianquan.jianshen.admin.authorization.runtime.catalog;

import com.fasterxml.jackson.databind.ObjectMapper;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.Test;
import org.springframework.mock.web.MockHttpServletRequest;
import org.springframework.security.core.context.SecurityContextHolder;
import top.egon.cola.platform.tianquan.jianshen.contract.authorization.ExecutionAuthorizationContract;
import top.egon.cola.platform.tianquan.jianshen.contract.authorization.ExecutionScopeAuthorizationContract;
import top.egon.cola.platform.tianquan.jianshen.core.rule.Rbac3RuleViolation;
import top.egon.cola.platform.tianquan.shoubing.contract.ServiceIdentityPrincipal;
import top.egon.cola.platform.tianquan.shoubing.contract.ServiceTokenContext;
import top.egon.cola.platform.tianquan.shoubing.starter.security.IdpAuthenticationToken;
import top.egon.cola.platform.tianquan.shoubing.starter.security.RequiresServiceScope;

import java.net.URI;
import java.nio.charset.StandardCharsets;
import java.time.Instant;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.concurrent.atomic.AtomicBoolean;

import static org.junit.jupiter.api.Assertions.*;
import static org.mockito.ArgumentMatchers.*;
import static org.mockito.Mockito.*;

class ExecutionScopeAuthorizationControllerTest {
    private static final URI ISSUER = URI.create("https://idp.example/20");
    private static final Instant NOW = Instant.parse("2026-10-31T00:00:00Z");
    @AfterEach void clear() { SecurityContextHolder.clearContext(); }

    @Test
    void missing_scoped_permission_is_rejected_before_sensitive_body_access() throws Exception {
        var service = mock(ExecutionGrantAuthorizationService.class); var controller = new ExecutionGrantAuthorizationController(service, new ObjectMapper().findAndRegisterModules());
        var caller = caller(Set.of(ExecutionAuthorizationContract.SERVICE_SCOPE));
        SecurityContextHolder.getContext().setAuthentication(new IdpAuthenticationToken(caller, List.of(), ISSUER));
        var read = new AtomicBoolean();
        var request = new MockHttpServletRequest() { @Override public jakarta.servlet.ServletInputStream getInputStream() { read.set(true); throw new AssertionError("body must remain unread"); } };
        assertThrows(Rbac3RuleViolation.class, () -> controller.decideScopes(request, caller)); assertFalse(read.get()); verifyNoInteractions(service);
        var method = ExecutionGrantAuthorizationController.class.getMethod("decideScopes", jakarta.servlet.http.HttpServletRequest.class, ServiceIdentityPrincipal.class);
        assertEquals(ExecutionScopeAuthorizationContract.SERVICE_SCOPE, method.getAnnotation(RequiresServiceScope.class).value());
    }

    @Test
    void verified_scoped_call_uses_a_noncacheable_separate_response_and_closed_request_decoder() throws Exception {
        var mapper = new ObjectMapper().findAndRegisterModules(); var service = mock(ExecutionGrantAuthorizationService.class); var controller = new ExecutionGrantAuthorizationController(service, mapper);
        var caller = caller(Set.of(ExecutionScopeAuthorizationContract.SERVICE_SCOPE));
        SecurityContextHolder.getContext().setAuthentication(new IdpAuthenticationToken(caller, List.of(), ISSUER));
        var request = new ExecutionAuthorizationContract.Request("agent", "9" + "1".repeat(62), "ENC:v1:test:nonce:sealed-fixture");
        var base = new ExecutionAuthorizationContract.Decision(request.grantId(), ISSUER.toString(), "20", "identity-sub", "https://agent.example", "TIANJI_MEMORY_READ",
                "00000000-0000-0000-0000-000000000123", "a".repeat(64), false, NOW.plusSeconds(60), NOW.plusSeconds(30), 2, 3);
        var scoped = new ExecutionScopeAuthorizationContract.Decision(base, "60", NOW, Map.of());
        when(service.decideScopes(caller, ISSUER, request)).thenReturn(scoped);
        var http = new MockHttpServletRequest("POST", ExecutionScopeAuthorizationContract.PATH); http.setContentType("application/json"); http.setContent(mapper.writeValueAsBytes(request));
        var response = controller.decideScopes(http, caller); assertEquals(200, response.getStatusCode().value()); assertEquals(scoped, response.getBody());
        assertEquals("no-store", response.getHeaders().getCacheControl()); verify(service).decideScopes(caller, ISSUER, request); clearInvocations(service);
        http.setContent("{\"systemCode\":\"agent\",\"grantId\":123,\"ciphertext\":\"private-fixture\"}".getBytes(StandardCharsets.UTF_8));
        var failure = assertThrows(RuntimeException.class, () -> controller.decideScopes(http, caller)); assertFalse(failure.toString().contains("private-fixture")); verifyNoInteractions(service);
    }

    private static ServiceIdentityPrincipal caller(Set<String> scopes) {
        return new ServiceIdentityPrincipal("agent", "20", "agent", "45", URI.create("https://rbac.example"), 0, scopes,
                "platform", "agent", "test", "credential", NOW.minusSeconds(10), NOW.plusSeconds(100), "agent-client", ServiceTokenContext.TENANT);
    }
}
