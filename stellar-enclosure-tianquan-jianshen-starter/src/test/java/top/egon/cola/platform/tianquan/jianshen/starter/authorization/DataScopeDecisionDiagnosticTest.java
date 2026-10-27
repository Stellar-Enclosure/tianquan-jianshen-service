package top.egon.cola.platform.tianquan.jianshen.starter.authorization;

import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.Test;
import org.springframework.mock.web.MockHttpServletRequest;
import org.springframework.mock.web.MockHttpServletResponse;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.validation.beanvalidation.LocalValidatorFactoryBean;
import org.springframework.web.context.request.RequestContextHolder;
import org.springframework.web.context.request.ServletRequestAttributes;
import org.springframework.web.method.HandlerMethod;
import top.egon.cola.platform.tianquan.jianshen.contract.authorization.DataScopeDecision;
import top.egon.cola.platform.tianquan.jianshen.contract.authorization.Decision;
import top.egon.cola.platform.tianquan.jianshen.contract.authorization.SystemAuthorizationSnapshot;
import top.egon.cola.platform.tianquan.jianshen.contract.permission.*;
import top.egon.cola.platform.tianquan.jianshen.contract.permission.annotation.PermissionResource;
import top.egon.cola.platform.tianquan.jianshen.starter.permission.PermissionDenialAudit;
import top.egon.cola.platform.tianquan.jianshen.starter.permission.PermissionDenialDiagnostic;
import top.egon.cola.platform.tianquan.jianshen.starter.security.Rbac3AuthenticationToken;
import top.egon.cola.platform.tianquan.jianshen.starter.security.Rbac3UserDetails;
import top.egon.cola.platform.tianquan.shoubing.core.observability.IdpSecurityMetricsRecorder;
import top.egon.cola.platform.tianquan.shoubing.starter.security.IdpEndpointAuthenticationPolicy;
import top.egon.cola.platform.tianquan.shoubing.starter.security.IdpObservedVerificationComponent;
import top.egon.cola.platform.tianquan.shoubing.starter.security.IdpSecurityObservationFilter;
import top.egon.cola.platform.tianquan.shoubing.starter.security.domain.TokenAuditProofBO;
import java.net.URI;
import java.util.ArrayList;
import java.util.List;
import java.util.Map;
import java.util.Set;
import static org.junit.jupiter.api.Assertions.*;
import static org.mockito.ArgumentMatchers.*;
import static org.mockito.Mockito.*;
import static top.egon.cola.platform.tianquan.jianshen.starter.permission.PermissionRuntimeFixture.*;

class DataScopeDecisionDiagnosticTest {
    private final LocalValidatorFactoryBean validator = new LocalValidatorFactoryBean();
    private final IdpObservedVerificationComponent observations = mock(IdpObservedVerificationComponent.class);
    private final TokenAuditProofBO proof = new TokenAuditProofBO(URI.create("https://idp.example/tenants/20"),
            URI.create("https://api.example/shop"), "a".repeat(64), null, "b".repeat(64));
    private final PermissionManifest manifest = manifest(List.of(new PermissionManifest.ResourceDefinition("shop.api.read", ResourceType.API,
            Map.of("methods", List.of("GET"), "paths", List.of("/orders")), ResourceAccess.PROTECTED, all("order:read"), null,
            List.of(PermissionManifest.PrincipalType.USER), List.of(), new PermissionManifest.I18nReference("shop", "read"), DefinitionLifecycle.ACTIVE)));

    @AfterEach void clear() { SecurityContextHolder.clearContext(); RequestContextHolder.resetRequestAttributes(); validator.close(); }
    static class Handler {
        @PermissionResource(key="shop.api.read", type=ResourceType.API, labelPage="shop", labelKey="read")
        public void read() { }
    }

    @Test void recordsOnlyTheActualDeniedScopePolicyAfterTheStrictReceipt() throws Exception {
        var snapshot = snapshot(manifest, Set.of("order:read"));
        var events = new ArrayList<PermissionDenialDiagnostic>();
        var service = service(snapshot, events);
        var request = request();
        var response = new MockHttpServletResponse();
        when(observations.enabled()).thenReturn(true);
        when(observations.authorizationDenied(proof)).thenReturn(true);
        new IdpSecurityObservationFilter(observations, new IdpEndpointAuthenticationPolicy()).doFilter(request, response, (incoming, outgoing) -> {
            RequestContextHolder.setRequestAttributes(new ServletRequestAttributes(request, response));
            authenticate(snapshot);
            var decision = service.decideDataScope(new AuthorizationService.DataScopeRequest("order:read"));
            assertEquals(Decision.DENY, decision.decision());
            assertEquals("DATA_SCOPE_MISSING", decision.reasonCode());
        });
        assertEquals(1, events.size());
        var event = events.getFirst();
        assertEquals("DATA_SCOPE_POLICY", event.decisionKind());
        assertEquals("DATA_SCOPE_MISSING", event.reasonCode());
        assertEquals("shop.api.read", event.resourceKey());
        assertEquals(false, event.details().get("finalObjectDecision"));
        assertEquals("NOT_EVALUATED", event.details().get("scopeEvaluation"));
        assertEquals(response.getHeader("X-Permission-Decision-Id"), event.decisionId());
        assertEquals("order:read", event.permissionFacts().getFirst().code());
        assertFalse(event.toString().contains("allowedOrgIds"));
        verify(observations, times(1)).authorizationDenied(proof);
    }

    @Test void allowAndAnUnconfirmedDenialProduceNoScopeDiagnostic() throws Exception {
        var base = snapshot(manifest, Set.of("order:read"));
        var allowed = new DataScopeDecision(Decision.ALLOW, "ALLOW", "20", "60", "order:read", "TENANT_ALL", true,
                Set.of(), false, Set.of(), false, Set.of(), false, null, "3", 3, 2, 3, List.of(), NOW);
        var snapshot = withScopes(base, Map.of("order:read", allowed));
        var events = new ArrayList<PermissionDenialDiagnostic>();
        var service = service(snapshot, events);
        var request = request(); var response = new MockHttpServletResponse();
        when(observations.enabled()).thenReturn(true);
        new IdpSecurityObservationFilter(observations, new IdpEndpointAuthenticationPolicy()).doFilter(request, response, (incoming, outgoing) -> {
            RequestContextHolder.setRequestAttributes(new ServletRequestAttributes(request, response));
            authenticate(snapshot);
            assertEquals(Decision.ALLOW, service.decideDataScope(new AuthorizationService.DataScopeRequest("order:read")).decision());
        });
        assertTrue(events.isEmpty());
        RequestContextHolder.resetRequestAttributes(); SecurityContextHolder.clearContext();

        var deniedSnapshot = snapshot(manifest, Set.of("order:read"));
        var deniedService = service(deniedSnapshot, events);
        var rejectedRequest = request(); var rejectedResponse = new MockHttpServletResponse();
        when(observations.authorizationDenied(proof)).thenReturn(false);
        new IdpSecurityObservationFilter(observations, new IdpEndpointAuthenticationPolicy()).doFilter(rejectedRequest, rejectedResponse, (incoming, outgoing) -> {
            RequestContextHolder.setRequestAttributes(new ServletRequestAttributes(rejectedRequest, rejectedResponse));
            authenticate(deniedSnapshot);
            var failure = assertThrows(AuthorizationService.RuntimeUnavailableException.class,
                    () -> deniedService.decideDataScope(new AuthorizationService.DataScopeRequest("order:read")));
            assertEquals("OAUTH_AUDIT_DELIVERY_UNAVAILABLE", failure.reasonCode());
        });
        assertTrue(events.isEmpty());
    }

    @Test void unknownOrDifferentContextDoesNotInventHistoricalScopeEvidence() throws Exception {
        var evaluated = snapshot(manifest, Set.of("order:read"));
        var another = snapshot(manifest, Set.of("order:read"));
        var events = new ArrayList<PermissionDenialDiagnostic>();
        var service = service(evaluated, events);
        var request = request(); var response = new MockHttpServletResponse();
        when(observations.enabled()).thenReturn(true);
        when(observations.authorizationDenied(proof)).thenReturn(true);
        new IdpSecurityObservationFilter(observations, new IdpEndpointAuthenticationPolicy()).doFilter(request, response, (incoming, outgoing) -> {
            RequestContextHolder.setRequestAttributes(new ServletRequestAttributes(request, response));
            authenticate(another);
            assertEquals(Decision.DENY, service.decideDataScope(new AuthorizationService.DataScopeRequest("order:read")).decision());
        });
        assertTrue(events.isEmpty());
        RequestContextHolder.resetRequestAttributes(); SecurityContextHolder.clearContext();
        var unavailable = new DefaultAuthorizationService(() -> { throw new AuthorizationService.RuntimeUnavailableException("UNAVAILABLE", USER); },
                value -> AuthorizationService.OperationSodResult.allowed(), value -> AuthorizationService.FenceResult.allowed(NOW), CLOCK);
        var wrapper = new Rbac3ObservedAuthorizationService(unavailable, IdpSecurityMetricsRecorder.NOOP, observations, validator,
                new PermissionDenialAudit(() -> null, events::add, CLOCK), registry(manifest));
        var second = request(); var secondResponse = new MockHttpServletResponse();
        new IdpSecurityObservationFilter(observations, new IdpEndpointAuthenticationPolicy()).doFilter(second, secondResponse, (incoming, outgoing) -> {
            RequestContextHolder.setRequestAttributes(new ServletRequestAttributes(second, secondResponse));
            authenticate(evaluated);
            assertEquals(Decision.INDETERMINATE, wrapper.decideDataScope(new AuthorizationService.DataScopeRequest("order:read")).decision());
        });
        assertTrue(events.isEmpty());
    }

    @Test void scopeMetadataNeverCopiesDirectoryOrBusinessReferences() throws Exception {
        var decision = new DataScopeDecision(Decision.DENY, "DATA_SCOPE_DENIED", "20", "60", "order:read", "NONE", false,
                Set.of("private-org"), false, Set.of("private-dept"), false, Set.of("private-user"), false, null,
                "directory:9", 3, 2, 3, List.of("private-evidence"), NOW);
        var snapshot = withScopes(snapshot(manifest, Set.of("order:read")), Map.of("order:read", decision));
        var events = new ArrayList<PermissionDenialDiagnostic>();
        var service = service(snapshot, events); var request = request(); var response = new MockHttpServletResponse();
        when(observations.enabled()).thenReturn(true);
        when(observations.authorizationDenied(proof)).thenReturn(true);
        new IdpSecurityObservationFilter(observations, new IdpEndpointAuthenticationPolicy()).doFilter(request, response, (incoming, outgoing) -> {
            RequestContextHolder.setRequestAttributes(new ServletRequestAttributes(request, response));
            authenticate(snapshot);
            assertEquals(Decision.DENY, service.decideDataScope(new AuthorizationService.DataScopeRequest("order:read")).decision());
        });
        assertEquals("directory:9", events.getFirst().details().get("directoryVersion"));
        assertFalse(events.getFirst().toString().contains("private-org"));
        assertFalse(events.getFirst().toString().contains("private-dept"));
        assertFalse(events.getFirst().toString().contains("private-user"));
        assertFalse(events.getFirst().toString().contains("private-evidence"));
    }

    @Test void diagnosticSinkFailureDoesNotChangeTheScopeDecision() throws Exception {
        var snapshot = snapshot(manifest, Set.of("order:read"));
        validator.afterPropertiesSet();
        var delegate = new DefaultAuthorizationService(() -> new AuthorizationService.RuntimeAuthorizationContext(USER, snapshot, false),
                request -> AuthorizationService.OperationSodResult.allowed(), request -> AuthorizationService.FenceResult.allowed(NOW), CLOCK);
        var service = new Rbac3ObservedAuthorizationService(delegate, IdpSecurityMetricsRecorder.NOOP, observations, validator,
                new PermissionDenialAudit(() -> null, ignored -> { throw new IllegalStateException("sink unavailable"); }, CLOCK), registry(manifest));
        var request = request(); var response = new MockHttpServletResponse();
        when(observations.enabled()).thenReturn(true);
        when(observations.authorizationDenied(proof)).thenReturn(true);
        new IdpSecurityObservationFilter(observations, new IdpEndpointAuthenticationPolicy()).doFilter(request, response, (incoming, outgoing) -> {
            RequestContextHolder.setRequestAttributes(new ServletRequestAttributes(request, response));
            authenticate(snapshot);
            var result = service.decideDataScope(new AuthorizationService.DataScopeRequest("order:read"));
            assertEquals(Decision.DENY, result.decision());
            assertEquals("DATA_SCOPE_MISSING", result.reasonCode());
        });
    }

    private Rbac3ObservedAuthorizationService service(SystemAuthorizationSnapshot snapshot, List<PermissionDenialDiagnostic> events) {
        validator.afterPropertiesSet();
        var delegate = new DefaultAuthorizationService(() -> new AuthorizationService.RuntimeAuthorizationContext(USER, snapshot, false),
                request -> AuthorizationService.OperationSodResult.allowed(), request -> AuthorizationService.FenceResult.allowed(NOW), CLOCK);
        return new Rbac3ObservedAuthorizationService(delegate, IdpSecurityMetricsRecorder.NOOP, observations, validator,
                new PermissionDenialAudit(() -> null, events::add, CLOCK), registry(manifest));
    }
    private void authenticate(SystemAuthorizationSnapshot snapshot) {
        var auth = new Rbac3AuthenticationToken(new Rbac3UserDetails(USER, snapshot));
        auth.setDetails(proof); SecurityContextHolder.getContext().setAuthentication(auth);
    }
    private MockHttpServletRequest request() throws Exception {
        var request = new MockHttpServletRequest("GET", "/orders");
        request.setAttribute("org.springframework.web.servlet.HandlerMapping.bestMatchingHandler",
                new HandlerMethod(new Handler(), Handler.class.getMethod("read")));
        return request;
    }
    private static SystemAuthorizationSnapshot withScopes(SystemAuthorizationSnapshot s, Map<String, DataScopeDecision> scopes) {
        return new SystemAuthorizationSnapshot(s.tenantId(), s.identitySub(), s.rbac3UserId(), s.systemCode(), s.authVersion(),
                s.policyVersion(), s.activeRoleIds(), s.activeRoles(), s.landingRouteCode(), s.permissions(), s.resourceCodes(),
                scopes, s.fieldPolicies(), s.checksum(), s.generatedAt(), s.expiresAt(), s.permissionSnapshot(), s.policyBinding());
    }
}
