package top.egon.cola.platform.tianquan.jianshen.starter.field;

import com.fasterxml.jackson.databind.ObjectMapper;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.Test;
import org.springframework.security.core.context.SecurityContextHolder;
import top.egon.cola.component.common.desensitize.strategy.SensitiveStrategyRegistry;
import top.egon.cola.platform.tianquan.jianshen.contract.permission.*;
import top.egon.cola.platform.tianquan.jianshen.starter.security.CurrentRbac3User;
import java.util.*;
import static org.junit.jupiter.api.Assertions.*;
import static top.egon.cola.platform.tianquan.jianshen.starter.permission.PermissionRuntimeFixture.*;

class FieldReadPolicyTest {
    public static class Output { public String email = "ada@example.com"; public int total = 42; }
    private final PermissionManifest manifest = manifest(List.of(
            field(Output.class, "email", ResourceAccess.PROTECTED, new PermissionManifest.FieldPolicy(PermissionManifest.JsonFieldType.STRING,
                    all("field:plain"), all("field:masked"), all("field:write"), "EMAIL")),
            field(Output.class, "total", ResourceAccess.PUBLIC, null)));
    @AfterEach void clear() { SecurityContextHolder.clearContext(); }
    private String render(Set<String> permissions, Output value) throws Exception {
        authenticate(manifest, permissions); var registry = registry(manifest); var users = new CurrentRbac3User();
        return new ObjectMapper().registerModule(new Rbac3FieldJacksonModule(users, SensitiveStrategyRegistry.defaults(),
                registry, new PermissionFieldBindingGuard(registry, users))).writeValueAsString(value);
    }
    @Test void writeDoesNotGrantReadAndMissingReadOmitsTheKey() throws Exception {
        assertEquals("{\"total\":42}", render(Set.of("field:write"), new Output()));
    }
    @Test void plainDominatesMaskAndProjectionDoesNotMutateTheEntity() throws Exception {
        Output value = new Output();
        String masked = render(Set.of("field:masked"), value);
        assertFalse(masked.contains("ada@example.com"));
        assertEquals("ada@example.com", value.email);
        assertTrue(render(Set.of("field:plain", "field:masked"), value).contains("ada@example.com"));
    }
    @Test void aWriteScopeCannotExposeAReadFieldEvenWhenTheRoleHasBothCharacters() throws Exception {
        Set<String> granted = Set.of("field:plain", "field:write");
        authenticate(manifest, granted);
        var details = new CurrentRbac3User().require();
        SecurityContextHolder.getContext().setAuthentication(new top.egon.cola.platform.tianquan.jianshen.starter.security.Rbac3AuthenticationToken(
                details, List.of(new org.springframework.security.core.authority.SimpleGrantedAuthority("SCOPE_scope:write"))));
        var policy = new top.egon.cola.platform.tianquan.jianshen.starter.autoconfigure.Rbac3StarterProperties.UserScopePolicyProperties()
                .setEnabled(true).setPermissionScopes(Map.of("field:plain", Set.of("scope:read"), "field:write", Set.of("scope:write")));
        var registry = registry(manifest); var users = new CurrentRbac3User();
        var mapper = new ObjectMapper().registerModule(new Rbac3FieldJacksonModule(users, SensitiveStrategyRegistry.defaults(), registry,
                new PermissionFieldBindingGuard(registry, users, () -> null, policy)));
        assertEquals("{\"total\":42}", mapper.writeValueAsString(new Output()));
    }

    @Test void transportFieldProjectionNeverMutatesTheSharedInternalCodec() throws Exception {
        ObjectMapper internal = new ObjectMapper();
        var registry = registry(manifest); var users = new CurrentRbac3User();
        var factory = new PermissionJsonMapperFactory(users, SensitiveStrategyRegistry.defaults(), registry,
                new PermissionFieldBindingGuard(registry, users));
        ObjectMapper transport = factory.forTransport(internal);
        SecurityContextHolder.clearContext();
        assertTrue(internal.writeValueAsString(new Output()).contains("ada@example.com"));
        assertEquals("{}", transport.writeValueAsString(new Output()));
        assertFalse(internal.getRegisteredModuleIds().contains("Rbac3FieldJacksonModule"));
    }

    @Test void nonStringMaskingCannotChangeAJsonNumberIntoString() {
        assertThrows(IllegalArgumentException.class, () -> new PermissionManifest.FieldPolicy(PermissionManifest.JsonFieldType.NUMBER,
                null, all("field:masked"), null, "FIXED"));
    }
}
