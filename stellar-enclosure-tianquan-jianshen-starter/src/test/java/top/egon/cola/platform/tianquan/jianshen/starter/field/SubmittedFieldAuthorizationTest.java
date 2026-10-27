package top.egon.cola.platform.tianquan.jianshen.starter.field;

import com.fasterxml.jackson.annotation.JsonAlias;
import com.fasterxml.jackson.annotation.JsonProperty;
import com.fasterxml.jackson.core.type.TypeReference;
import com.fasterxml.jackson.databind.ObjectMapper;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.Test;
import org.springframework.security.core.context.SecurityContextHolder;
import top.egon.cola.component.common.desensitize.strategy.SensitiveStrategyRegistry;
import top.egon.cola.platform.tianquan.jianshen.contract.permission.*;
import top.egon.cola.platform.tianquan.jianshen.starter.permission.PermissionRuntimeFixture;
import top.egon.cola.platform.tianquan.jianshen.starter.permission.PermissionDenialAudit;
import top.egon.cola.platform.tianquan.jianshen.starter.permission.PermissionDenialDiagnostic;
import top.egon.cola.platform.tianquan.jianshen.starter.security.CurrentRbac3User;
import java.util.*;
import static org.junit.jupiter.api.Assertions.*;
import static top.egon.cola.platform.tianquan.jianshen.starter.permission.PermissionRuntimeFixture.*;

class SubmittedFieldAuthorizationTest {
    public static class Input {
        @JsonAlias("display_name") public String name;
        @JsonProperty(access = JsonProperty.Access.READ_ONLY) public String calculated;
        public List<Child> children;
    }
    public static class Child { public String secret; }
    public static class Handler {
        @top.egon.cola.platform.tianquan.jianshen.contract.permission.annotation.PermissionResource(
                key="shop.api.update", type=ResourceType.API, labelPage="shop", labelKey="update")
        public void update() { }
    }
    private final PermissionManifest.FieldPolicy write = new PermissionManifest.FieldPolicy(PermissionManifest.JsonFieldType.STRING,
            null, null, all("field:write"), null);
    private final PermissionManifest manifest = manifest(List.of(field(Input.class, "name", ResourceAccess.PROTECTED, write),
            field(Input.class, "calculated", ResourceAccess.PUBLIC, null), field(Input.class, "children", ResourceAccess.PUBLIC, null),
            field(Child.class, "secret", ResourceAccess.PROTECTED, write)));

    @AfterEach void clear() { SecurityContextHolder.clearContext(); org.springframework.web.context.request.RequestContextHolder.resetRequestAttributes(); }
    private ObjectMapper mapper(Set<String> permissions) {
        authenticate(manifest, permissions);
        var registry = registry(manifest); var users = new CurrentRbac3User();
        return new ObjectMapper().registerModule(new Rbac3FieldJacksonModule(users, SensitiveStrategyRegistry.defaults(),
                registry, new PermissionFieldBindingGuard(registry, users)));
    }
    @Test void explicitNullRequiresWriteAndOmissionDoesNot() throws Exception {
        var mapper = mapper(Set.of());
        assertThrows(Exception.class, () -> mapper.readValue("{\"name\":null}", Input.class));
        assertNull(mapper.readValue("{}", Input.class).name);
        assertNull(mapper(Set.of("field:write")).readValue("{\"name\":null}", Input.class).name);
    }
    @Test void aliasesUseTheActualWritableProperty() throws Exception {
        assertEquals("Ada", mapper(Set.of("field:write")).readValue("{\"display_name\":\"Ada\"}", Input.class).name);
        assertThrows(Exception.class, () -> mapper(Set.of()).readValue("{\"display_name\":\"Ada\"}", Input.class));
    }
    @Test void publicReadOnlyDoesNotBecomeWritableAndUnknownFieldsFail() {
        var mapper = mapper(Set.of("field:write"));
        assertThrows(Exception.class, () -> mapper.readValue("{\"calculated\":\"x\"}", Input.class));
        assertThrows(Exception.class, () -> mapper.readValue("{\"unknown\":null}", Input.class));
        assertThrows(Exception.class, () -> mapper.readValue("{\"name\":\"a\",\"display_name\":\"b\"}", Input.class));
    }
    @Test void nestedArraysAndWholeBatchRejectBeforeBusinessWrite() throws Exception {
        var mapper = mapper(Set.of());
        assertThrows(Exception.class, () -> mapper.readValue("{\"children\":[{\"secret\":null}]}", Input.class));
        int[] writes = {0};
        assertThrows(Exception.class, () -> {
            List<Input> batch = mapper.readValue("[{}, {\"name\":\"forbidden\"}]", new TypeReference<>() { });
            batch.forEach(value -> writes[0]++);
        });
        assertEquals(0, writes[0]);
        var fields = SubmittedFieldSet.capture(new ObjectMapper().readTree("{\"children\":[{\"secret\":null}]}"));
        assertTrue(fields.paths().contains("children[0].secret"));
    }
    @Test void multipleFieldsKeepIndependentWriteAndReadOnlyChecks() throws Exception {
        var allowed = mapper(Set.of("field:write")).readValue(
                "{\"name\":\"Ada\",\"children\":[{\"secret\":\"value\"}]}", Input.class);
        assertEquals("Ada", allowed.name);
        assertEquals("value", allowed.children.getFirst().secret);
        assertThrows(Exception.class, () -> mapper(Set.of("field:write")).readValue(
                "{\"name\":\"Ada\",\"calculated\":\"forbidden\"}", Input.class));
    }

    @Test void deniedFieldWritesCaptureTheDeclaredRuleWithoutCapturingSubmittedValues() {
        var events = new ArrayList<PermissionDenialDiagnostic>();
        var request = new org.springframework.mock.web.MockHttpServletRequest();
        var response = new org.springframework.mock.web.MockHttpServletResponse();
        org.springframework.web.context.request.RequestContextHolder.setRequestAttributes(
                new org.springframework.web.context.request.ServletRequestAttributes(request, response));
        authenticate(manifest, Set.of());
        var registry = registry(manifest);
        var policy = new top.egon.cola.platform.tianquan.jianshen.starter.autoconfigure.Rbac3StarterProperties.UserScopePolicyProperties();
        var guard = new PermissionFieldBindingGuard(registry, new CurrentRbac3User(), () -> null, policy,
                new PermissionDenialAudit(() -> null, events::add, CLOCK));
        var mapper = new ObjectMapper().registerModule(new Rbac3FieldJacksonModule(new CurrentRbac3User(),
                SensitiveStrategyRegistry.defaults(), registry, guard));
        assertThrows(Exception.class, () -> mapper.readValue("{\"name\":\"private-business-value\"}", Input.class));
        assertEquals(1, events.size());
        var event = events.getFirst();
        assertEquals("FIELD_WRITE", event.decisionKind());
        assertEquals("FIELD_PERMISSION_DENIED", event.reasonCode());
        assertEquals("shop.field.Input.name", event.resourceKey());
        assertEquals(Map.of("mode", "ALL", "codes", List.of("field:write")), event.requirement());
        assertEquals(false, event.permissionFacts().getFirst().granted());
        assertEquals(response.getHeader("X-Permission-Decision-Id"), event.decisionId());
        assertFalse(event.toString().contains("private-business-value"));
        events.clear();
        assertThrows(org.springframework.security.authorization.AuthorizationDeniedException.class,
                () -> guard.require(Input.class, new SubmittedFieldSet(Set.of("calculated")), Set.of("calculated")));
        assertEquals("FIELD_INPUT_READ_ONLY", events.getFirst().reasonCode());
        assertEquals(false, events.getFirst().details().get("inputBindingWritable"));
    }

    @Test void deniedFieldScopeDoesNotTurnAWriteGrantIntoAccess() {
        var events = new ArrayList<PermissionDenialDiagnostic>();
        authenticate(manifest, Set.of("field:write"));
        var registry = registry(manifest);
        var policy = new top.egon.cola.platform.tianquan.jianshen.starter.autoconfigure.Rbac3StarterProperties.UserScopePolicyProperties()
                .setEnabled(true).setPermissionScopes(Map.of("field:write", Set.of("scope:write")));
        var guard = new PermissionFieldBindingGuard(registry, new CurrentRbac3User(), () -> null, policy,
                new PermissionDenialAudit(() -> null, events::add, CLOCK));
        assertThrows(org.springframework.security.authorization.AuthorizationDeniedException.class,
                () -> guard.require(Input.class, new SubmittedFieldSet(Set.of("name")), Set.of("name")));
        assertEquals("OAUTH_SCOPE_DENIED", events.getFirst().reasonCode());
        assertEquals(List.of("scope:write"), events.getFirst().permissionFacts().getFirst().missingScopes());
        assertTrue(events.getFirst().permissionFacts().getFirst().granted());
        assertFalse(events.getFirst().permissionFacts().getFirst().scopeQualified());
    }

    @Test void deniedFieldDoesNotPublishWhenStrictAuditReceiptFails() {
        var events = new ArrayList<PermissionDenialDiagnostic>();
        authenticate(manifest, Set.of());
        var observer = org.mockito.Mockito.mock(top.egon.cola.platform.tianquan.shoubing.starter.security.IdpObservedVerificationComponent.class);
        var proof = new top.egon.cola.platform.tianquan.shoubing.starter.security.domain.TokenAuditProofBO(
                java.net.URI.create("https://idp.example/tenants/20"), java.net.URI.create("https://api.example/shop"),
                "a".repeat(64), null, "b".repeat(64));
        org.mockito.Mockito.when(observer.enabled()).thenReturn(true);
        org.mockito.Mockito.when(observer.authorizationDenied(proof)).thenReturn(false);
        var guard = new PermissionFieldBindingGuard(registry(manifest), new CurrentRbac3User(), () -> null,
                new top.egon.cola.platform.tianquan.jianshen.starter.autoconfigure.Rbac3StarterProperties.UserScopePolicyProperties(),
                new PermissionDenialAudit(() -> observer, events::add, CLOCK));
        var marker = new top.egon.cola.platform.tianquan.shoubing.starter.security.domain.IdpAuthorizationObservationContextBO();
        try {
            top.egon.cola.platform.tianquan.shoubing.starter.security.rpc.IdpRpcSecurityContext.with(USER, "original-proof", proof, marker)
                    .run(() -> assertThrows(top.egon.cola.platform.tianquan.jianshen.starter.client.Rbac3AuthorizationClient.AuthorizationUnavailableException.class,
                            () -> guard.require(Input.class, new SubmittedFieldSet(Set.of("name")), Set.of("name"))));
            assertTrue(events.isEmpty());
            assertFalse(marker.isConfirmed());
        } finally { marker.close(); }
    }

    @Test void unknownOrDuplicateInputIsRecordedWithoutItsSubmittedNamesOrValues() throws Exception {
        var api = new PermissionManifest.ResourceDefinition("shop.api.update", ResourceType.API,
                Map.of("methods", List.of("POST"), "paths", List.of("/orders")), ResourceAccess.PROTECTED, all("order:read"), null,
                List.of(PermissionManifest.PrincipalType.USER), List.of(), new PermissionManifest.I18nReference("shop", "update"), DefinitionLifecycle.ACTIVE);
        var resources = new ArrayList<>(manifest.resources()); resources.add(api);
        var combined = manifest(resources);
        var events = new ArrayList<PermissionDenialDiagnostic>();
        var request = new org.springframework.mock.web.MockHttpServletRequest("POST", "/orders");
        var response = new org.springframework.mock.web.MockHttpServletResponse();
        request.setAttribute("org.springframework.web.servlet.HandlerMapping.bestMatchingHandler",
                new org.springframework.web.method.HandlerMethod(new Handler(), Handler.class.getMethod("update")));
        org.springframework.web.context.request.RequestContextHolder.setRequestAttributes(
                new org.springframework.web.context.request.ServletRequestAttributes(request, response));
        authenticate(combined, Set.of("field:write", "order:read"));
        var registry = registry(combined);
        var guard = new PermissionFieldBindingGuard(registry, new CurrentRbac3User(), () -> null,
                new top.egon.cola.platform.tianquan.jianshen.starter.autoconfigure.Rbac3StarterProperties.UserScopePolicyProperties(),
                new PermissionDenialAudit(() -> null, events::add, CLOCK));
        var mapper = new ObjectMapper().registerModule(new Rbac3FieldJacksonModule(new CurrentRbac3User(),
                SensitiveStrategyRegistry.defaults(), registry, guard));
        assertThrows(Exception.class, () -> mapper.readValue("{\"private-unknown-name\":\"private-value\"}", Input.class));
        assertEquals(1, events.size());
        var event = events.getFirst();
        assertEquals("FIELD_INPUT", event.decisionKind());
        assertEquals("FIELD_BINDING_UNKNOWN_OR_DUPLICATE", event.reasonCode());
        assertEquals("shop.api.update", event.resourceKey());
        assertFalse(event.resolvePermissionSources());
        assertFalse(event.toString().contains("private-unknown-name"));
        assertFalse(event.toString().contains("private-value"));
        assertEquals(event.decisionId(), response.getHeader("X-Permission-Decision-Id"));
        events.clear();
        assertThrows(Exception.class, () -> mapper.readValue("{\"name\":\"first\",\"display_name\":\"second\"}", Input.class));
        assertEquals("FIELD_INPUT", events.getFirst().decisionKind());
        assertFalse(events.getFirst().toString().contains("first"));
        assertFalse(events.getFirst().toString().contains("second"));
    }
}
