package top.egon.cola.platform.tianquan.jianshen.starter.field;

import com.fasterxml.jackson.annotation.JsonAlias;
import com.fasterxml.jackson.annotation.JsonProperty;
import com.fasterxml.jackson.databind.ObjectMapper;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.Test;
import org.springframework.http.HttpStatus;
import org.springframework.http.MediaType;
import org.springframework.http.ResponseEntity;
import org.springframework.http.converter.json.MappingJackson2HttpMessageConverter;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.test.web.servlet.MockMvc;
import org.springframework.test.web.servlet.setup.MockMvcBuilders;
import org.springframework.web.bind.annotation.ExceptionHandler;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RestController;
import org.springframework.web.bind.annotation.RestControllerAdvice;
import org.springframework.web.context.request.RequestContextHolder;
import top.egon.cola.component.common.desensitize.strategy.SensitiveStrategyRegistry;
import top.egon.cola.platform.tianquan.jianshen.contract.permission.PermissionManifest;
import top.egon.cola.platform.tianquan.jianshen.contract.permission.ResourceAccess;
import top.egon.cola.platform.tianquan.jianshen.contract.permission.ResourceType;
import top.egon.cola.platform.tianquan.jianshen.contract.permission.annotation.FieldPermissions;
import top.egon.cola.platform.tianquan.jianshen.contract.permission.annotation.PermissionGroup;
import top.egon.cola.platform.tianquan.jianshen.contract.permission.annotation.PermissionResource;
import top.egon.cola.platform.tianquan.jianshen.starter.permission.PermissionPolicyRegistry;
import top.egon.cola.platform.tianquan.jianshen.starter.security.CurrentRbac3User;
import top.egon.cola.platform.tianquan.jianshen.starter.web.Rbac3AuthorizationExceptionHandler;

import java.util.List;
import java.util.Set;
import java.util.concurrent.atomic.AtomicInteger;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.Mockito.spy;
import static org.mockito.Mockito.times;
import static org.mockito.Mockito.verify;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.post;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;
import static top.egon.cola.platform.tianquan.jianshen.starter.permission.PermissionRuntimeFixture.all;
import static top.egon.cola.platform.tianquan.jianshen.starter.permission.PermissionRuntimeFixture.authenticate;
import static top.egon.cola.platform.tianquan.jianshen.starter.permission.PermissionRuntimeFixture.field;
import static top.egon.cola.platform.tianquan.jianshen.starter.permission.PermissionRuntimeFixture.manifest;
import static top.egon.cola.platform.tianquan.jianshen.starter.permission.PermissionRuntimeFixture.registry;

class StrictFieldRequestBodyAdviceTest {

    public static class Input {
        @PermissionResource(key = "shop.field.Input.name", type = ResourceType.FIELD, labelPage = "shop", labelKey = "name")
        @FieldPermissions(valueType = PermissionManifest.JsonFieldType.STRING, write = @PermissionGroup(codes = {"field:write"}))
        @JsonAlias("display_name")
        public String name;

        @PermissionResource(key = "shop.field.Input.calculated", type = ResourceType.FIELD, labelPage = "shop", labelKey = "calculated")
        @JsonProperty(access = JsonProperty.Access.READ_ONLY)
        public String calculated;

        @PermissionResource(key = "shop.field.Input.children", type = ResourceType.FIELD, labelPage = "shop", labelKey = "children")
        public List<Child> children;
    }

    public static class Child {
        @PermissionResource(key = "shop.field.Child.secret", type = ResourceType.FIELD, labelPage = "shop", labelKey = "secret")
        @FieldPermissions(valueType = PermissionManifest.JsonFieldType.STRING, write = @PermissionGroup(codes = {"field:write"}))
        public String secret;
    }

    @RestController
    static class TestController {
        final AtomicInteger invocations = new AtomicInteger();

        @PostMapping(path = "/strict/save", consumes = MediaType.APPLICATION_JSON_VALUE)
        String save(@RequestBody @StrictFieldBinding(requiredFields = {"name"}) Input input) {
            invocations.incrementAndGet();
            return input.name == null ? "null" : input.name;
        }

        @PostMapping(path = "/strict/bounded", consumes = MediaType.APPLICATION_JSON_VALUE)
        String bounded(@RequestBody @StrictFieldBinding(maxBytes = 32) Input input) {
            invocations.incrementAndGet();
            return "ok";
        }
    }

    @RestControllerAdvice
    static class InvalidRequestAdvice {
        @ExceptionHandler(IllegalArgumentException.class)
        ResponseEntity<String> badRequest(IllegalArgumentException error) {
            return ResponseEntity.status(HttpStatus.BAD_REQUEST).body(error.getMessage());
        }
    }

    private final PermissionManifest.FieldPolicy write = new PermissionManifest.FieldPolicy(
            PermissionManifest.JsonFieldType.STRING, null, null, all("field:write"), null);
    private final PermissionManifest manifest = manifest(List.of(
            field(Input.class, "name", ResourceAccess.PROTECTED, write),
            field(Input.class, "calculated", ResourceAccess.PUBLIC, null),
            field(Input.class, "children", ResourceAccess.PUBLIC, null),
            field(Child.class, "secret", ResourceAccess.PROTECTED, write)));
    private final PermissionPolicyRegistry registry = registry(manifest);

    @AfterEach
    void cleanup() {
        SecurityContextHolder.clearContext();
        RequestContextHolder.resetRequestAttributes();
    }

    private MockMvc mvc(TestController controller, PermissionFieldBindingGuard guard, boolean withJacksonModule) {
        ObjectMapper baseMapper = new ObjectMapper();
        var binder = new StrictSubmittedFieldBinder(baseMapper, guard, registry);
        ObjectMapper transportMapper = withJacksonModule
                ? new PermissionJsonMapperFactory(new CurrentRbac3User(), SensitiveStrategyRegistry.defaults(), registry, guard)
                        .forTransport(baseMapper)
                : baseMapper;
        return MockMvcBuilders.standaloneSetup(controller)
                .setControllerAdvice(new Rbac3AuthorizationExceptionHandler(), new InvalidRequestAdvice(), new StrictFieldRequestBodyAdvice(binder))
                .setMessageConverters(new MappingJackson2HttpMessageConverter(transportMapper))
                .build();
    }

    @Test
    void enforcesFieldWritePermissionsWithoutDoubleVerificationWhenModuleIsActive() throws Exception {
        var controller = new TestController();
        var guard = spy(new PermissionFieldBindingGuard(registry, new CurrentRbac3User()));
        MockMvc mvc = mvc(controller, guard, true);

        authenticate(manifest, Set.of());
        mvc.perform(post("/strict/save").contentType(MediaType.APPLICATION_JSON).content("{\"name\":null}"))
                .andExpect(status().isForbidden());
        assertEquals(0, controller.invocations.get());

        authenticate(manifest, Set.of("field:write"));
        mvc.perform(post("/strict/save").contentType(MediaType.APPLICATION_JSON)
                        .content("{\"display_name\":\"Ada\",\"children\":[{\"secret\":\"top\"}]}"))
                .andExpect(status().isOk());
        assertEquals(1, controller.invocations.get());
        verify(guard, times(1)).require(eq(Input.class), any(), eq(Set.of("name", "children")));
        verify(guard, times(1)).require(eq(Child.class), any(), eq(Set.of("secret")));
    }

    @Test
    void rejectsMissingRequiredUnknownDuplicateTrailingCoercedReadOnlyAndOversizedPayloads() throws Exception {
        var controller = new TestController();
        var guard = new PermissionFieldBindingGuard(registry, new CurrentRbac3User());
        MockMvc mvc = mvc(controller, guard, false);
        authenticate(manifest, Set.of("field:write"));

        mvc.perform(post("/strict/save").contentType(MediaType.APPLICATION_JSON).content("{}"))
                .andExpect(status().isBadRequest());
        mvc.perform(post("/strict/save").contentType(MediaType.APPLICATION_JSON).content("{\"name\":\"Ada\",\"extra\":1}"))
                .andExpect(status().isBadRequest());
        mvc.perform(post("/strict/save").contentType(MediaType.APPLICATION_JSON).content("{\"name\":\"Ada\",\"display_name\":\"Bob\"}"))
                .andExpect(status().isBadRequest());
        mvc.perform(post("/strict/save").contentType(MediaType.APPLICATION_JSON).content("{\"name\":\"Ada\",\"name\":\"Bob\"}"))
                .andExpect(status().isBadRequest());
        mvc.perform(post("/strict/save").contentType(MediaType.APPLICATION_JSON).content("{\"name\":\"Ada\"} {}"))
                .andExpect(status().isBadRequest());
        mvc.perform(post("/strict/save").contentType(MediaType.APPLICATION_JSON).content("{\"name\":123}"))
                .andExpect(status().isBadRequest());
        mvc.perform(post("/strict/save").contentType(MediaType.APPLICATION_JSON).content("[]"))
                .andExpect(status().isBadRequest());
        mvc.perform(post("/strict/bounded").contentType(MediaType.APPLICATION_JSON).content("{\"name\":\"" + "a".repeat(64) + "\"}"))
                .andExpect(status().isBadRequest());
        mvc.perform(post("/strict/save").contentType(MediaType.APPLICATION_JSON).content("{\"name\":\"Ada\",\"calculated\":\"forged\"}"))
                .andExpect(status().isForbidden());
        assertEquals(0, controller.invocations.get());
    }
}
