package top.egon.cola.platform.tianquan.jianshen.admin.config.runtime;

import com.fasterxml.jackson.annotation.JsonProperty;
import com.fasterxml.jackson.databind.ObjectMapper;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.Test;
import org.springframework.boot.autoconfigure.AutoConfigurations;
import org.springframework.boot.env.YamlPropertySourceLoader;
import org.springframework.boot.http.converter.autoconfigure.HttpMessageConvertersAutoConfiguration;
import org.springframework.boot.jackson.autoconfigure.JacksonAutoConfiguration;
import org.springframework.boot.jackson2.autoconfigure.Jackson2AutoConfiguration;
import org.springframework.boot.test.context.runner.WebApplicationContextRunner;
import org.springframework.boot.webmvc.autoconfigure.WebMvcAutoConfiguration;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.core.io.ClassPathResource;
import org.springframework.core.io.InputStreamResource;
import org.springframework.http.MediaType;
import org.springframework.http.ResponseEntity;
import org.springframework.http.converter.ByteArrayHttpMessageConverter;
import org.springframework.http.converter.ResourceHttpMessageConverter;
import org.springframework.http.converter.StringHttpMessageConverter;
import org.springframework.http.converter.json.MappingJackson2HttpMessageConverter;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.test.web.servlet.MockMvc;
import org.springframework.test.web.servlet.setup.MockMvcBuilders;
import org.springframework.web.bind.annotation.*;
import org.springframework.web.servlet.mvc.method.annotation.RequestMappingHandlerAdapter;
import top.egon.cola.component.common.desensitize.strategy.SensitiveStrategyRegistry;
import top.egon.cola.platform.tianquan.jianshen.contract.authorization.*;
import top.egon.cola.platform.tianquan.jianshen.contract.permission.*;
import top.egon.cola.platform.tianquan.jianshen.contract.permission.annotation.PermissionResource;
import top.egon.cola.platform.tianquan.jianshen.starter.cache.SingleFlightSnapshotLoader;
import top.egon.cola.platform.tianquan.jianshen.starter.client.Rbac3AuthorizationClient;
import top.egon.cola.platform.tianquan.jianshen.starter.field.*;
import top.egon.cola.platform.tianquan.jianshen.starter.permission.*;
import top.egon.cola.platform.tianquan.jianshen.starter.security.*;
import top.egon.cola.platform.tianquan.jianshen.starter.web.Rbac3AuthorizationExceptionHandler;
import top.egon.cola.platform.tianquan.shoubing.contract.AuthenticationContext;
import top.egon.cola.platform.tianquan.shoubing.contract.IdentityPrincipal;
import top.egon.cola.platform.tianquan.shoubing.starter.security.VerifiedUserTokenCarrier;

import java.io.ByteArrayInputStream;
import java.time.Clock;
import java.time.Instant;
import java.time.ZoneOffset;
import java.util.List;
import java.util.Map;
import java.util.Set;

import static org.assertj.core.api.Assertions.assertThat;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.*;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.*;

/** Boot's actual converter auto-configuration in a mock servlet context, without a server or host scan. */
class Rbac3PermissionMvcAutoConfigurationTest {
    @AfterEach
    void clear() { SecurityContextHolder.clearContext(); }

    @Test
    void actualApplicationPreferenceUsesFieldEnforcementForTheFirstDtoReaderAndWriter() throws Exception {
        var properties = new YamlPropertySourceLoader().load("application", new ClassPathResource("application.yml"));
        String preferred = properties.stream().map(value -> value.getProperty("spring.http.converters.preferred-json-mapper"))
                .filter(java.util.Objects::nonNull).map(Object::toString).findFirst().orElseThrow();
        assertThat(preferred).isEqualTo("jackson2");
        runner(preferred).run(context -> {
            assertThat(context).hasNotFailed();
            assertDtoConverters(context.getBean(RequestMappingHandlerAdapter.class), context.getBean("jacksonObjectMapper", ObjectMapper.class));
            var fixture = context.getBean(Fixture.class);
            MockMvc mvc = mvc(context);
            fixture.authenticate(Set.of("order:write", "field:masked"));
            mvc.perform(post("/fixture/save").contentType(MediaType.APPLICATION_JSON).content("{\"name\":null}"))
                    .andExpect(status().isForbidden());
            assertThat(fixture.writes).isZero();
            fixture.authenticate(Set.of("order:write", "field:write", "field:masked"));
            mvc.perform(post("/fixture/save").contentType(MediaType.APPLICATION_JSON).content("{\"calculated\":\"forged\"}"))
                    .andExpect(status().isForbidden());
            assertThat(fixture.writes).isZero();
            String response = mvc.perform(post("/fixture/save").contentType(MediaType.APPLICATION_JSON).content("{\"name\":null}"))
                    .andExpect(status().isOk()).andReturn().getResponse().getContentAsString();
            assertThat(fixture.writes).isEqualTo(1);
            assertThat(response).contains("email").doesNotContain("ada@example.com");
        });
    }

    @Test
    void jackson3DefaultCannotBypassFieldsOrPrecedeExistingStringByteAndStreamWriters() {
        runner("jackson").run(context -> {
            assertThat(context).hasNotFailed();
            var adapter = context.getBean(RequestMappingHandlerAdapter.class);
            var converters = adapter.getMessageConverters();
            assertThat(converters).anyMatch(org.springframework.http.converter.json.JacksonJsonHttpMessageConverter.class::isInstance);
            var json = assertDtoConverters(adapter, context.getBean("jacksonObjectMapper", ObjectMapper.class));
            for (Class<?> type : List.of(StringHttpMessageConverter.class, ByteArrayHttpMessageConverter.class, ResourceHttpMessageConverter.class)) {
                int index = java.util.stream.IntStream.range(0, converters.size()).filter(i -> type.isInstance(converters.get(i))).findFirst().orElseThrow();
                assertThat(index).isLessThan(converters.indexOf(json));
            }
            var fixture = context.getBean(Fixture.class);
            fixture.authenticate(Set.of("order:write", "field:masked"));
            MockMvc mvc = mvc(context);
            mvc.perform(post("/fixture/save").contentType(MediaType.APPLICATION_JSON).content("{\"name\":null}"))
                    .andExpect(status().isForbidden());
            assertThat(fixture.writes).isZero();
            mvc.perform(get("/fixture/raw")).andExpect(status().isOk()).andExpect(content().string("{\"ok\":true}"));
            mvc.perform(get("/fixture/bytes")).andExpect(status().isOk()).andExpect(content().bytes(new byte[]{1, 2, 3}));
            mvc.perform(get("/fixture/stream")).andExpect(status().isOk()).andExpect(content().bytes(new byte[]{4, 5, 6}));
        });
    }

    private WebApplicationContextRunner runner(String preferred) {
        return new WebApplicationContextRunner().withConfiguration(AutoConfigurations.of(JacksonAutoConfiguration.class,
                        Jackson2AutoConfiguration.class, HttpMessageConvertersAutoConfiguration.class, WebMvcAutoConfiguration.class))
                .withPropertyValues("spring.http.converters.preferred-json-mapper=" + preferred,
                        "egon.cola.platform.tianquan.jianshen.enabled=true")
                .withUserConfiguration(TestConfiguration.class, Rbac3PermissionMvcConfiguration.class);
    }

    private MappingJackson2HttpMessageConverter assertDtoConverters(RequestMappingHandlerAdapter adapter, ObjectMapper shared) {
        var reader = adapter.getMessageConverters().stream().filter(value -> value.canRead(Input.class, MediaType.APPLICATION_JSON)).findFirst().orElseThrow();
        var writer = adapter.getMessageConverters().stream().filter(value -> value.canWrite(Output.class, MediaType.APPLICATION_JSON)).findFirst().orElseThrow();
        assertThat(reader).isInstanceOf(MappingJackson2HttpMessageConverter.class);
        assertThat(writer).isSameAs(reader);
        var json = (MappingJackson2HttpMessageConverter) reader;
        assertThat(json.getObjectMapper()).isNotSameAs(shared);
        assertThat(json.getObjectMapper().getRegisteredModuleIds()).contains("Rbac3FieldJacksonModule");
        assertThat(shared.getRegisteredModuleIds()).doesNotContain("Rbac3FieldJacksonModule");
        return json;
    }

    private MockMvc mvc(org.springframework.web.context.WebApplicationContext context) {
        return MockMvcBuilders.webAppContextSetup(context).addFilter((request, response, chain) -> {
            VerifiedUserTokenCarrier.set((jakarta.servlet.http.HttpServletRequest) request, "verified-user-fixture");
            chain.doFilter(request, response);
        }).build();
    }

    @Configuration(proxyBeanMethods = false)
    static class TestConfiguration {
        @Bean("jacksonObjectMapper") ObjectMapper mapper() { return new ObjectMapper().findAndRegisterModules(); }
        @Bean Fixture fixture() { return new Fixture(); }
        @Bean PermissionJsonMapperFactory permissionFields(Fixture fixture) { return fixture.mapperFactory; }
        @Bean Endpoint endpoint(Fixture fixture) { return new Endpoint(fixture); }
        @Bean Rbac3AuthorizationExceptionHandler advice() { return new Rbac3AuthorizationExceptionHandler(); }
    }

    public static class Input { public String name; @JsonProperty(access = JsonProperty.Access.READ_ONLY) public String calculated; }
    public static class Output { public String email = "ada@example.com"; }

    static final class Fixture {
        private static final Instant NOW = Instant.parse("2026-10-25T00:00:00Z");
        private static final Clock CLOCK = Clock.fixed(NOW, ZoneOffset.UTC);
        private static final CatalogScope SCOPE = new CatalogScope("10", "20", "commerce", "shop", "default", "test");
        private final PermissionManifest manifest = new PermissionManifest("1.0", new PermissionManifest.Application("commerce", "shop"),
                new PermissionManifest.Producer("shop-java", PermissionManifest.ProducerKind.JAVA, PermissionManifest.SnapshotMode.FULL,
                        List.of("shop."), List.of("app"), List.of("app"), false),
                new PermissionManifest.Artifact("https://example.com/repo", "a".repeat(40), "build", "1"), List.of(),
                List.of("order:write", "field:write", "field:plain", "field:masked"), List.of(
                        new PermissionManifest.ResourceDefinition("shop.api.save", ResourceType.API, Map.of("methods", List.of("POST"), "paths", List.of("/fixture/save")),
                                ResourceAccess.PROTECTED, all("order:write"), null, List.of(PermissionManifest.PrincipalType.USER), List.of(),
                                new PermissionManifest.I18nReference("shop", "save"), DefinitionLifecycle.ACTIVE),
                        field(Input.class, "name", ResourceAccess.PROTECTED, new PermissionManifest.FieldPolicy(PermissionManifest.JsonFieldType.STRING, null, null, all("field:write"), null)),
                        field(Input.class, "calculated", ResourceAccess.PUBLIC, null),
                        field(Output.class, "email", ResourceAccess.PROTECTED, new PermissionManifest.FieldPolicy(PermissionManifest.JsonFieldType.STRING, all("field:plain"), all("field:masked"), null, "EMAIL"))), List.of(), List.of());
        private final IdentityPrincipal identity = new IdentityPrincipal("30", "20", "40", Set.of("https://api.example/shop"), NOW.minusSeconds(10), NOW.plusSeconds(100), AuthenticationContext.password());
        private final PermissionPolicyRegistry registry = new PermissionPolicyRegistry(manifest, "a".repeat(64), CLOCK, List.of(SCOPE));
        private final CurrentRbac3User users = new CurrentRbac3User();
        private Set<String> codes = Set.of();
        private final Rbac3AuthorizationClient client = (system, caller) -> snapshot();
        private final PermissionExecutionGuard execution = new PermissionExecutionGuard(registry, users, new SingleFlightSnapshotLoader(client, "shop", CLOCK));
        private final PermissionJsonMapperFactory mapperFactory = new PermissionJsonMapperFactory(users, SensitiveStrategyRegistry.defaults(), registry, new PermissionFieldBindingGuard(registry, users));
        private int writes;

        private void authenticate(Set<String> codes) { this.codes = codes; SecurityContextHolder.getContext().setAuthentication(new Rbac3AuthenticationToken(new Rbac3UserDetails(identity, snapshot()))); }
        private SystemAuthorizationSnapshot snapshot() {
            var digests = new PermissionManifestCanonicalizer().digests(manifest);
            var view = new EffectivePermissionSnapshot("https://idp.example/tenants/20", "30", SCOPE, "1", "2", "3",
                    new EffectivePermissionSnapshot.ActiveRoleContext("shop", List.of("50"), List.of("50")), codes.stream().sorted().toList(), NOW.plusSeconds(30));
            return new SystemAuthorizationSnapshot("20", "30", "60", "shop", 2, 3, List.of("50"), null, null, codes,
                    manifest.resources().stream().map(PermissionManifest.ResourceDefinition::key).collect(java.util.stream.Collectors.toSet()),
                    Map.of(), Map.of(), "sum", NOW, view.snapshotExpiresAt(), view,
                    new RuntimePolicyBinding("shop-java", "1", "a".repeat(64), digests.policyDigest(), digests.manifestDigest()));
        }
        private static PermissionRequirement all(String code) { return new PermissionRequirement(PermissionMode.ALL, List.of(code)); }
        private static PermissionManifest.ResourceDefinition field(Class<?> dto, String name, ResourceAccess access, PermissionManifest.FieldPolicy policy) {
            return new PermissionManifest.ResourceDefinition("shop.field." + dto.getSimpleName() + "." + name, ResourceType.FIELD,
                    Map.of("dto", dto.getCanonicalName(), "property", name), access, null, policy, List.of(PermissionManifest.PrincipalType.USER), List.of(),
                    new PermissionManifest.I18nReference("shop", name), DefinitionLifecycle.ACTIVE);
        }
    }

    @RestController
    static class Endpoint {
        private final Fixture fixture;
        Endpoint(Fixture fixture) { this.fixture = fixture; }
        @PostMapping("/fixture/save")
        @PermissionResource(key = "shop.api.save", type = ResourceType.API, labelPage = "shop", labelKey = "save")
        Output save(@RequestBody Input input) { fixture.execution.requireExecution("shop.api.save"); fixture.writes++; return new Output(); }
        @GetMapping(value = "/fixture/raw", produces = "application/json") ResponseEntity<String> raw() { return ResponseEntity.ok("{\"ok\":true}"); }
        @GetMapping("/fixture/bytes") ResponseEntity<byte[]> bytes() { return ResponseEntity.ok(new byte[]{1, 2, 3}); }
        @GetMapping("/fixture/stream") ResponseEntity<InputStreamResource> stream() { return ResponseEntity.ok(new InputStreamResource(new ByteArrayInputStream(new byte[]{4, 5, 6}))); }
    }
}
