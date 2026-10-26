package top.egon.cola.platform.tianquan.jianshen.yuheng.security;

import org.junit.jupiter.api.Test;
import reactor.core.publisher.Mono;
import top.egon.cola.component.yuheng.contract.protocol.AccessZone;
import top.egon.cola.component.yuheng.contract.protocol.GatewayProtocol;
import top.egon.cola.component.yuheng.core.context.GatewayPrincipal;
import top.egon.cola.component.yuheng.core.security.AuthorizationDecision;
import top.egon.cola.component.yuheng.core.security.GatewayAuthContext;
import top.egon.cola.component.yuheng.core.security.SecurityDecision;

import java.time.Instant;
import java.util.List;
import java.util.Set;

import static org.junit.jupiter.api.Assertions.assertEquals;

class GatewayFailClosedSecurityMatrixTest {

    private static final Instant NOW = Instant.parse("2026-07-30T08:00:00Z");

    @Test
    void scopeRuntimeFailuresNeverBecomeAuthorizationAllow() {
        var providers = List.of(
                new Rbac3BizAppScopeAuthorizationProvider(
                        ignored -> {
                            throw new IllegalStateException("redis lost");
                        }),
                new Rbac3BizAppScopeAuthorizationProvider(
                        ignored -> {
                            throw new IllegalArgumentException("scope malformed");
                        }));

        for (Rbac3BizAppScopeAuthorizationProvider provider : providers) {
            var decision = Mono.from(provider.authorize(context())).block();
            assertEquals(SecurityDecision.ERROR, decision.decision());
            assertEquals("TIANQUAN_JIANSHEN_SCOPE_RUNTIME_UNAVAILABLE",
                    decision.reason());
        }
    }

    @Test
    void preservesBusinessAndApplicationDenials() {
        var denials = List.of(
                AuthorizationDecision.deny("TIANQUAN_JIANSHEN_BUSINESS_SCOPE_DENIED"),
                AuthorizationDecision.deny("TIANQUAN_JIANSHEN_APPLICATION_SCOPE_DENIED"));

        for (AuthorizationDecision denial : denials) {
            var provider = new Rbac3BizAppScopeAuthorizationProvider(
                    ignored -> denial);

            assertEquals(denial,
                    Mono.from(provider.authorize(context())).block());
        }
    }

    @Test
    void mandatoryScopeAndFineDenialsShareOneRealStrictProducerResult() throws Exception {
        var validator = new org.springframework.validation.beanvalidation.LocalValidatorFactoryBean(); validator.afterPropertiesSet();
        var authority = org.mockito.Mockito.mock(top.egon.cola.platform.tianquan.shoubing.starter.state.IdentityAuthorityClient.class);
        org.mockito.Mockito.when(authority.appendAudit(org.mockito.ArgumentMatchers.any())).thenAnswer(call -> {
            top.egon.cola.platform.tianquan.shoubing.core.audit.TokenUsageAuditEvent event = call.getArgument(0);
            return new top.egon.cola.platform.tianquan.shoubing.contract.state.IdentityAuditReceipt(
                    "00000000-0000-0000-0000-000000000001", event.eventId(),
                    top.egon.cola.platform.tianquan.shoubing.core.audit.TokenUsageAuditFingerprint.of(event),
                    event.issuer().toASCIIString(), "reviewed-gateway", event.resource(), "STORED", NOW);
        });
        var issuer = java.net.URI.create("https://idp.example/tenants/1001"); var resource = java.net.URI.create("https://api.example/payments");
        top.egon.cola.platform.tianquan.shoubing.core.observability.IdpSecurityMetricsRecorder metrics = sample -> { };
        var producer = new top.egon.cola.platform.tianquan.shoubing.starter.audit.TokenUsageAuditComponent(verifiedIssuer -> authority,
                java.time.Clock.fixed(NOW, java.time.ZoneOffset.UTC), validator, metrics);
        var converter = (top.egon.cola.platform.tianquan.shoubing.starter.security.domain.converter.TokenUsageAuditEventConverter)
                Class.forName("top.egon.cola.platform.tianquan.shoubing.starter.security.domain.converter.TokenUsageAuditEventConverterImpl").getConstructor().newInstance();
        var usage = new top.egon.cola.platform.tianquan.shoubing.starter.audit.OAuthUsageObservationProperties(true, issuer, false,
                top.egon.cola.platform.tianquan.shoubing.starter.observability.IdpSecurityObservationReceiverEnum.BIZ);
        var observations = new top.egon.cola.platform.tianquan.shoubing.starter.security.IdpObservedVerificationComponent(producer, converter,
                usage, metrics, java.time.Clock.fixed(NOW, java.time.ZoneOffset.UTC), validator, resource);
        var proof = new top.egon.cola.platform.tianquan.shoubing.starter.security.domain.TokenAuditProofBO(issuer, resource, "a".repeat(64), null, "b".repeat(64));
        var evidence = new top.egon.cola.platform.tianquan.shoubing.yuheng.security.domain.GatewayVerifiedIdentityBO(proof, Set.of("payments:other"));
        var principal = new GatewayPrincipal("operator", "USER", "1001", null, true, java.util.Map.of(), evidence);
        var scoped = new GatewayAuthContext(AccessZone.PUBLIC, GatewayProtocol.HTTP, "payments.read", "payments", "policy", "/payments", "GET",
                Set.of("bearer"), principal, "127.0.0.1", "trace", "request", NOW.plusSeconds(5), "release", java.util.Map.of(), Set.of("payments:read"));
        var scope = new top.egon.cola.platform.tianquan.shoubing.yuheng.security.IdpOAuthScopeAuthorizationProvider(observations, metrics, validator);
        var fine = new Rbac3BizAppScopeAuthorizationProvider(ignored -> AuthorizationDecision.deny("BIZ_DENIED"), observations, metrics, validator);
        java.util.Map<Object, java.util.Map.Entry<Object, Runnable>> states = new java.util.HashMap<>();
        java.util.function.BiFunction<Object, java.util.function.Supplier<java.util.Map.Entry<Object, Runnable>>, Object> owner =
                (type, factory) -> states.computeIfAbsent(type, ignored -> factory.get()).getKey();
        try {
            var decisions = Mono.from(scope.authorize(scoped)).flatMap(first -> Mono.from(fine.authorize(scoped)).map(second -> List.of(first, second)))
                    .contextWrite(context -> context.put(GatewayAuthContext.class, owner)).block();
            assertEquals(SecurityDecision.DENY, decisions.get(0).decision()); assertEquals(SecurityDecision.DENY, decisions.get(1).decision());
            org.mockito.Mockito.verify(authority, org.mockito.Mockito.times(1)).appendAudit(org.mockito.ArgumentMatchers.any());
            var marker = (top.egon.cola.platform.tianquan.shoubing.starter.security.domain.IdpAuthorizationObservationContextBO)
                    states.get(top.egon.cola.platform.tianquan.shoubing.starter.security.domain.IdpAuthorizationObservationContextBO.class).getKey();
            org.junit.jupiter.api.Assertions.assertTrue(marker.isConfirmed());
            states.values().forEach(entry -> entry.getValue().run());
            org.junit.jupiter.api.Assertions.assertFalse(marker.isActive());
            states.clear();
            org.mockito.Mockito.doThrow(new IllegalStateException("controlled identity SQL authority outage"))
                    .when(authority).appendAudit(org.mockito.ArgumentMatchers.any());
            var failed = Mono.from(scope.authorize(scoped)).flatMap(first -> Mono.from(fine.authorize(scoped)).map(second -> List.of(first, second)))
                    .contextWrite(context -> context.put(GatewayAuthContext.class, owner)).block();
            assertEquals(SecurityDecision.ERROR, failed.get(0).decision()); assertEquals(SecurityDecision.ERROR, failed.get(1).decision());
            org.mockito.Mockito.verify(authority, org.mockito.Mockito.times(2)).appendAudit(org.mockito.ArgumentMatchers.any());
        } finally { states.values().forEach(entry -> entry.getValue().run()); validator.close(); }
    }

    private static GatewayAuthContext context() {
        return new GatewayAuthContext(
                AccessZone.PUBLIC, GatewayProtocol.HTTP, "operation", "route",
                "policy", "/payments", "POST", Set.of("bearer"),
                new GatewayPrincipal(
                        "user", "USER", "tenant", null, true, java.util.Map.of()),
                "127.0.0.1", "trace", "request", NOW.plusSeconds(5),
                "release");
    }
}
