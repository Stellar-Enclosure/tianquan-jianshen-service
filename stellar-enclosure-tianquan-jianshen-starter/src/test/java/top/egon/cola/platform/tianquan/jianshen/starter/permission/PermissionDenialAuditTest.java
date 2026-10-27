package top.egon.cola.platform.tianquan.jianshen.starter.permission;

import org.junit.jupiter.api.Test;
import top.egon.cola.platform.tianquan.jianshen.starter.client.Rbac3AuthorizationClient;
import top.egon.cola.platform.tianquan.shoubing.starter.security.IdpObservedVerificationComponent;
import top.egon.cola.platform.tianquan.shoubing.starter.security.domain.IdpAuthorizationObservationContextBO;
import top.egon.cola.platform.tianquan.shoubing.starter.security.domain.TokenAuditProofBO;
import top.egon.cola.platform.tianquan.shoubing.starter.security.rpc.IdpRpcSecurityContext;
import java.net.URI;
import static org.junit.jupiter.api.Assertions.*;
import static org.mockito.Mockito.*;
import static top.egon.cola.platform.tianquan.jianshen.starter.permission.PermissionRuntimeFixture.*;

class PermissionDenialAuditTest {
    private final IdpObservedVerificationComponent observations=mock(IdpObservedVerificationComponent.class);
    private final PermissionDenialAudit audit=new PermissionDenialAudit(()->observations);
    private final TokenAuditProofBO proof=new TokenAuditProofBO(URI.create("https://idp.example/tenants/20"),
            URI.create("https://api.example/shop"),"a".repeat(64),null,"b".repeat(64));
    @Test void rpcApiAndFieldDenialsShareTheExistingStrictReceiptMarker(){
        when(observations.enabled()).thenReturn(true);when(observations.authorizationDenied(proof)).thenReturn(true);
        var marker=new IdpAuthorizationObservationContextBO();
        try{
            IdpRpcSecurityContext.with(USER,"proof",proof,marker).run(()->{
                assertInstanceOf(org.springframework.security.authorization.AuthorizationDeniedException.class,audit.denied("PERMISSION_DENIED"));
                assertInstanceOf(org.springframework.security.authorization.AuthorizationDeniedException.class,audit.denied("FIELD_ACCESS_DENIED"));
            });
            verify(observations,times(1)).authorizationDenied(proof);assertTrue(marker.isConfirmed());
        }finally{marker.close();}
    }
    @Test void missingCommittedAuditReceiptRemainsUnavailable(){
        when(observations.enabled()).thenReturn(true);when(observations.authorizationDenied(proof)).thenReturn(false);
        var marker=new IdpAuthorizationObservationContextBO();
        try{
            IdpRpcSecurityContext.with(USER,"proof",proof,marker).run(()->{
                assertInstanceOf(Rbac3AuthorizationClient.AuthorizationUnavailableException.class,audit.denied("FIELD_ACCESS_DENIED"));
                assertInstanceOf(Rbac3AuthorizationClient.AuthorizationUnavailableException.class,audit.denied("PERMISSION_DENIED"));
            });
            verify(observations,times(1)).authorizationDenied(proof);assertFalse(marker.isConfirmed());
        }finally{marker.close();}
    }

    @Test void servletDenialExposesOnlyAnOpaqueIdAndKeepsTheExternalReason() {
        var request = new org.springframework.mock.web.MockHttpServletRequest();
        var response = new org.springframework.mock.web.MockHttpServletResponse();
        org.springframework.web.context.request.RequestContextHolder.setRequestAttributes(
                new org.springframework.web.context.request.ServletRequestAttributes(request, response));
        var logger = (ch.qos.logback.classic.Logger) org.slf4j.LoggerFactory.getLogger(PermissionDenialAudit.class);
        var events = new ch.qos.logback.core.read.ListAppender<ch.qos.logback.classic.spi.ILoggingEvent>();
        events.start(); logger.addAppender(events);
        org.slf4j.MDC.put("traceId", "trace-123");
        try {
            var denied = audit.denied("PERMISSION_DENIED", "OAUTH_SCOPE_DENIED", "shop.api.update");
            assertEquals("PERMISSION_DENIED", denied.getMessage());
            String decision = response.getHeader("X-Permission-Decision-Id");
            assertNotNull(decision);
            assertEquals(decision, java.util.UUID.fromString(decision).toString());
            String message = events.list.getLast().getFormattedMessage();
            assertTrue(message.contains("decisionId=" + decision));
            assertTrue(message.contains("traceId=trace-123"));
            assertTrue(message.contains("reasonCode=OAUTH_SCOPE_DENIED"));
            assertTrue(message.contains("resourceKey=shop.api.update"));
            assertFalse(message.contains("original-verified-user-proof"));
        } finally {
            logger.detachAppender(events); events.stop();
            org.slf4j.MDC.remove("traceId");
            org.springframework.web.context.request.RequestContextHolder.resetRequestAttributes();
        }
    }

    @Test void capturesOnlyRequiredPermissionFactsAndDoesNotChangeTheDenialWhenTheSinkFails() {
        var policy = new top.egon.cola.platform.tianquan.jianshen.contract.permission.PermissionManifest.ResourceDefinition(
                "shop.api.read", top.egon.cola.platform.tianquan.jianshen.contract.permission.ResourceType.API,
                java.util.Map.of("methods", java.util.List.of("GET"), "paths", java.util.List.of("/orders")),
                top.egon.cola.platform.tianquan.jianshen.contract.permission.ResourceAccess.PROTECTED, all("order:read"), null,
                java.util.List.of(top.egon.cola.platform.tianquan.jianshen.contract.permission.PermissionManifest.PrincipalType.USER),
                java.util.List.of("api:read"), new top.egon.cola.platform.tianquan.jianshen.contract.permission.PermissionManifest.I18nReference("shop", "read"),
                top.egon.cola.platform.tianquan.jianshen.contract.permission.DefinitionLifecycle.ACTIVE);
        var manifest = manifest(java.util.List.of(policy));
        var snapshot = snapshot(manifest, java.util.Set.of("order:read", "order:write"));
        var scopePolicy = new UserPermissionScopePolicy(new top.egon.cola.platform.tianquan.jianshen.starter.autoconfigure.Rbac3StarterProperties.UserScopePolicyProperties()
                .setEnabled(true).setPermissionScopes(java.util.Map.of("order:read", java.util.Set.of("scope:read"))));
        var captured = new java.util.ArrayList<PermissionDenialDiagnostic>();
        var audit = new PermissionDenialAudit(() -> null, captured::add, CLOCK);
        var denied = audit.denied("PERMISSION_DENIED", "OAUTH_SCOPE_DENIED", policy.key(), snapshot,
                policy, java.util.Set.of(), java.util.Set.of(), scopePolicy);
        assertEquals("PERMISSION_DENIED", denied.getMessage());
        assertEquals(1, captured.size());
        var event = captured.getFirst();
        assertEquals(java.util.List.of("api:read"), event.missingResourceScopes());
        assertEquals(java.util.List.of("order:read"), event.permissionFacts().stream().map(PermissionDenialDiagnostic.PermissionFact::code).toList());
        assertTrue(event.permissionFacts().getFirst().granted());
        assertFalse(event.permissionFacts().getFirst().scopeQualified());
        assertEquals(java.util.List.of("scope:read"), event.permissionFacts().getFirst().missingScopes());
        assertFalse(event.toString().contains("order:write"));
        var failing = new PermissionDenialAudit(() -> null, ignored -> {throw new IllegalStateException("unavailable");}, CLOCK);
        assertEquals("PERMISSION_DENIED", failing.denied("PERMISSION_DENIED", "PERMISSION_DENIED", policy.key(), snapshot,
                policy, java.util.Set.of(), java.util.Set.of(), scopePolicy).getMessage());
        captured.clear();
        when(observations.enabled()).thenReturn(true);
        when(observations.authorizationDenied(proof)).thenReturn(false);
        var strict = new PermissionDenialAudit(() -> observations, captured::add, CLOCK);
        var marker = new IdpAuthorizationObservationContextBO();
        try {
            IdpRpcSecurityContext.with(USER, "proof", proof, marker).run(() -> assertInstanceOf(
                    Rbac3AuthorizationClient.AuthorizationUnavailableException.class,
                    strict.denied("PERMISSION_DENIED", "OAUTH_SCOPE_DENIED", policy.key(), snapshot,
                            policy, java.util.Set.of(), java.util.Set.of(), scopePolicy)));
            assertTrue(captured.isEmpty());
        } finally { marker.close(); }
    }
}
