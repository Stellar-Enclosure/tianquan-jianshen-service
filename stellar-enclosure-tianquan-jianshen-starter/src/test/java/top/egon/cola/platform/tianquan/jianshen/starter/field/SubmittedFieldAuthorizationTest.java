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
    private final PermissionManifest.FieldPolicy write = new PermissionManifest.FieldPolicy(PermissionManifest.JsonFieldType.STRING,
            null, null, all("field:write"), null);
    private final PermissionManifest manifest = manifest(List.of(field(Input.class, "name", ResourceAccess.PROTECTED, write),
            field(Input.class, "calculated", ResourceAccess.PUBLIC, null), field(Input.class, "children", ResourceAccess.PUBLIC, null),
            field(Child.class, "secret", ResourceAccess.PROTECTED, write)));

    @AfterEach void clear() { SecurityContextHolder.clearContext(); }
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
}
