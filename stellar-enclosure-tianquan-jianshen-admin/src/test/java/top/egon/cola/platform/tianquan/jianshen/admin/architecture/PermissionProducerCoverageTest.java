package top.egon.cola.platform.tianquan.jianshen.admin.architecture;

import com.fasterxml.jackson.core.type.TypeReference;
import com.fasterxml.jackson.databind.ObjectMapper;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.condition.EnabledIfSystemProperty;
import org.springframework.context.annotation.ClassPathScanningCandidateComponentProvider;
import org.springframework.core.type.filter.AnnotationTypeFilter;
import org.springframework.web.bind.annotation.RestController;
import org.springframework.web.servlet.mvc.method.RequestMappingInfo;
import org.springframework.web.servlet.mvc.method.annotation.RequestMappingHandlerMapping;
import top.egon.cola.platform.tianquan.jianshen.contract.permission.PermissionManifest;
import top.egon.cola.platform.tianquan.jianshen.contract.permission.PermissionManifestReader;
import top.egon.cola.platform.tianquan.jianshen.contract.permission.ResourceAccess;
import top.egon.cola.platform.tianquan.jianshen.contract.permission.ResourceType;
import top.egon.cola.platform.tianquan.jianshen.contract.permission.annotation.PermissionResource;

import java.lang.reflect.Field;
import java.lang.reflect.Method;
import java.lang.reflect.ParameterizedType;
import java.lang.reflect.Type;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.ArrayList;
import java.util.HashSet;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.TreeMap;
import java.util.TreeSet;

import static org.assertj.core.api.Assertions.assertThat;

/** Compares javac artifacts with real Spring mappings and Jackson's reachable DTO properties. */
@EnabledIfSystemProperty(named = "permission.producer.enabled", matches = "true")
class PermissionProducerCoverageTest {
    private static final String ROOT = "top.egon.cola.platform.tianquan.jianshen.admin.";
    private static final Set<String> EXTERNAL_CONTRACTS = Set.of(
            "top.egon.cola.component.common.core.pojo.ResultRecord",
            "top.egon.cola.platform.tianquan.jianshen.contract.activation.ActiveRoleSetView",
            "top.egon.cola.platform.tianquan.jianshen.contract.activation.ReplaceActiveRolesRequest",
            "top.egon.cola.platform.tianquan.jianshen.contract.activation.ReplaceActiveRolesResult",
            "top.egon.cola.platform.tianquan.jianshen.contract.activation.RoleActivationCandidateView",
            "top.egon.cola.platform.tianquan.jianshen.contract.auth.Rbac3AboutView",
            "top.egon.cola.platform.tianquan.jianshen.contract.authorization.AuthorizationDecision",
            "top.egon.cola.platform.tianquan.jianshen.contract.authorization.DataScopeDecision",
            "top.egon.cola.platform.tianquan.jianshen.contract.authorization.ExecutionAuthorizationContract$Decision",
            "top.egon.cola.platform.tianquan.jianshen.contract.authorization.ExecutionAuthorizationContract$Request",
            "top.egon.cola.platform.tianquan.jianshen.contract.authorization.ExecutionScopeAuthorizationContract$Decision",
            "top.egon.cola.platform.tianquan.jianshen.contract.authorization.ServiceExecutionAuthorizationContract$Decision",
            "top.egon.cola.platform.tianquan.jianshen.contract.authorization.ServiceExecutionAuthorizationContract$Request",
            "top.egon.cola.platform.tianquan.jianshen.contract.authorization.FieldPolicyDecision",
            "top.egon.cola.platform.tianquan.jianshen.contract.authorization.ServicePolicySnapshot",
            "top.egon.cola.platform.tianquan.jianshen.contract.authorization.SystemAuthorizationSnapshot",
            "top.egon.cola.platform.tianquan.jianshen.contract.participation.BusinessParticipationCommand",
            "top.egon.cola.platform.tianquan.jianshen.contract.permission.ActivationDescriptor",
            "top.egon.cola.platform.tianquan.jianshen.contract.permission.CatalogScope",
            "top.egon.cola.platform.tianquan.jianshen.contract.permission.DeploymentQualificationRequest",
            "top.egon.cola.platform.tianquan.jianshen.contract.permission.EffectivePermissionSnapshot",
            "top.egon.cola.platform.tianquan.jianshen.contract.permission.FieldCatalogSnapshot",
            "top.egon.cola.platform.tianquan.jianshen.contract.permission.ManifestDigests",
            "top.egon.cola.platform.tianquan.jianshen.contract.permission.ManifestRegistrationReceipt",
            "top.egon.cola.platform.tianquan.jianshen.core.registration.PermissionManifestDiff$Result",
            "top.egon.cola.platform.tianquan.shoubing.contract.ServiceIdentityPrincipal");
    private final ObjectMapper json = new ObjectMapper().findAndRegisterModules();

    @Test
    void everyManagedHttpMappingAndReachableDtoPropertyHasExactlyOneExportedResource() throws Exception {
        List<PermissionManifest> fragments = fragments();
        Map<String, PermissionManifest.ResourceDefinition> resources = new TreeMap<>();
        for (var fragment : fragments) for (var resource : fragment.resources()) {
            assertThat(resources.put(resource.key(), resource)).as(resource.key()).isNull();
        }
        var scanner = new ClassPathScanningCandidateComponentProvider(false);
        var environment = new org.springframework.core.env.StandardEnvironment();
        environment.getPropertySources().addFirst(new org.springframework.core.env.MapPropertySource("producer-coverage",
                Map.of("egon.cola.platform.tianquan.jianshen.enabled", "true", "egon.tianquan-jianshen.execution-grants.enabled", "true",
                        "egon.tianquan-jianshen.service-execution-grants.enabled", "true")));
        scanner.setEnvironment(environment);
        scanner.addIncludeFilter(new AnnotationTypeFilter(RestController.class));
        var mappings = new Mappings();
        Set<String> apiKeys = new TreeSet<>();
        Set<String> fields = new TreeSet<>();
        Set<String> external = new TreeSet<>();
        for (var candidate : scanner.findCandidateComponents(ROOT)) {
            // Only production classes are packaged; test fixtures may use the same Java package.
            if (!Files.isRegularFile(Path.of("target/classes", candidate.getBeanClassName().replace('.', '/') + ".class"))) continue;
            Class<?> controller = Class.forName(candidate.getBeanClassName(), false, getClass().getClassLoader());
            for (Method method : controller.getDeclaredMethods()) {
                RequestMappingInfo mapping = mappings.mapping(method, controller);
                if (mapping == null) continue;
                PermissionResource declaration = method.getAnnotation(PermissionResource.class);
                assertThat(declaration).as(method.toGenericString()).isNotNull();
                assertThat(apiKeys.add(declaration.key())).isTrue();
                var exported = resources.get(declaration.key());
                assertThat(exported).as(declaration.key()).isNotNull();
                assertThat(exported.type()).isEqualTo(ResourceType.API);
                assertThat(exported.access()).isEqualTo(declaration.access());
                assertThat(strings(exported.target().get("paths"))).containsExactlyInAnyOrderElementsOf(mapping.getPatternValues());
                Set<String> methods = new TreeSet<>();
                mapping.getMethodsCondition().getMethods().forEach(value -> methods.add(value.name()));
                if (methods.contains("GET")) methods.add("HEAD");
                assertThat(strings(exported.target().get("methods"))).containsExactlyInAnyOrderElementsOf(methods);
                walk(method.getGenericReturnType(), true, resources, fields, external, new HashSet<>());
                for (Class<?> adapterInput : explicitInputs(controller, method)) {
                    walk(adapterInput, false, resources, fields, external, new HashSet<>());
                }
                if (controller.getSimpleName().equals("PermissionCatalogActivationController") && method.getName().equals("versions")) {
                    walk(top.egon.cola.platform.tianquan.jianshen.admin.registration.catalog.repository.PermissionCatalogActivationRepository.History.class,
                            true, resources, fields, external, new HashSet<>());
                }
                for (Type parameter : method.getGenericParameterTypes()) {
                    walk(parameter, false, resources, fields, external, new HashSet<>());
                }
            }
        }
        assertThat(apiKeys).hasSize(112).contains("tianquan-jianshen.api.runtime.executionGrantScopes");
        assertThat(fields).hasSize(620);
        assertThat(resources.values().stream().filter(value -> value.type() == ResourceType.API)
                .map(PermissionManifest.ResourceDefinition::key).toList()).containsExactlyInAnyOrderElementsOf(apiKeys);
        assertThat(resources.values().stream().filter(value -> value.type() == ResourceType.FIELD)
                .map(PermissionManifest.ResourceDefinition::key).toList()).containsExactlyInAnyOrderElementsOf(fields);
        assertThat(external).containsExactlyInAnyOrderElementsOf(EXTERNAL_CONTRACTS);
    }

    private List<Class<?>> explicitInputs(Class<?> controller, Method method) {
        if (controller.getSimpleName().equals("ExecutionGrantAuthorizationController")
                && Set.of("decide", "decideScopes").contains(method.getName())) {
            return List.of(top.egon.cola.platform.tianquan.jianshen.contract.authorization.ExecutionAuthorizationContract.Request.class);
        }
        if (controller.getSimpleName().equals("ServiceExecutionGrantAuthorizationController") && method.getName().equals("decide")) {
            return List.of(top.egon.cola.platform.tianquan.jianshen.contract.authorization.ServiceExecutionAuthorizationContract.Request.class);
        }
        return List.of();
    }

    @Test
    void definitionsAndLabelsResolveEveryDeclaredRequirement() throws Exception {
        var fragment = fragments().getFirst();
        var definitions = fragment.permissionDefinitions().stream().map(PermissionManifest.PermissionDefinition::code).collect(java.util.stream.Collectors.toSet());
        var messages = fragment.messages().stream().map(value -> value.pageCode() + ":" + value.key()).collect(java.util.stream.Collectors.toSet());
        assertThat(definitions).contains("system:role-permission:read", "system:role-permission:manage", "system:data-rule:manage");
        for (var resource : fragment.resources()) {
            assertThat(messages).contains(resource.i18n().pageCode() + ":" + resource.i18n().labelKey());
            if (resource.requirement() != null) {
                for (var group : resource.requirement().groups()) assertThat(definitions).containsAll(group.codes());
            }
            if (resource.fieldPolicy() != null) {
                for (var group : java.util.stream.Stream.of(resource.fieldPolicy().plainRead(), resource.fieldPolicy().maskedRead(), resource.fieldPolicy().write()).filter(java.util.Objects::nonNull).toList()) {
                    assertThat(definitions).containsAll(group.codes());
                }
            }
        }
    }

    private void walk(Type generic, boolean output, Map<String, PermissionManifest.ResourceDefinition> resources,
                      Set<String> fields, Set<String> external, Set<String> visiting) throws Exception {
        if (generic instanceof ParameterizedType parameterized) {
            for (Type argument : parameterized.getActualTypeArguments()) walk(argument, output, resources, fields, external, visiting);
            generic = parameterized.getRawType();
        }
        if (!(generic instanceof Class<?> type) || type.isPrimitive() || type.isEnum()) return;
        if (type.isArray()) { walk(type.componentType(), output, resources, fields, external, visiting); return; }
        if (!type.getName().startsWith(ROOT)) {
            if (type.getName().startsWith("top.egon.")) external.add(type.getName());
            return;
        }
        if (!visiting.add(type.getName() + output)) return;
        var dto = json.constructType(type);
        var description = output ? json.getSerializationConfig().introspect(dto) : json.getDeserializationConfig().introspect(dto);
        for (var property : description.findProperties()) {
            if (property.getPrimaryMember() == null) continue;
            Field field = type.getDeclaredField(property.getInternalName());
            PermissionResource declaration = field.getAnnotation(PermissionResource.class);
            assertThat(declaration).as(type.getName() + ":" + property.getName()).isNotNull();
            var resource = resources.get(declaration.key());
            assertThat(resource).as(declaration.key()).isNotNull();
            assertThat(resource.type()).isEqualTo(ResourceType.FIELD);
            assertThat(resource.target()).containsEntry("dto", type.getCanonicalName()).containsEntry("property", property.getName());
            fields.add(declaration.key());
            walk(field.getGenericType(), output, resources, fields, external, visiting);
        }
    }

    private List<PermissionManifest> fragments() throws Exception {
        List<PermissionManifest> fragments = new ArrayList<>();
        for (Path path : List.of(Path.of("target/classes/META-INF/permissions/fragment-v1.json"))) {
            assertThat(path).isRegularFile();
            var manifest = new PermissionManifestReader().read(json.readValue(Files.readString(path), new TypeReference<Map<String, Object>>() { }));
            assertThat(manifest.producer().id()).isEqualTo("tianquan-jianshen-java");
            assertThat(manifest.producer().ownedKeyPrefixes()).containsExactly("tianquan-jianshen.api.", "tianquan-jianshen.field.");
            assertThat(manifest.producer().snapshotMode()).isEqualTo(PermissionManifest.SnapshotMode.PARTIAL);
            assertThat(manifest.producer().expectedModules()).containsExactlyInAnyOrder(
                    "stellar-enclosure-tianquan-jianshen-admin");
            fragments.add(manifest);
        }
        return fragments;
    }

    @SuppressWarnings("unchecked")
    private List<String> strings(Object value) { return (List<String>) value; }

    private static final class Mappings extends RequestMappingHandlerMapping {
        RequestMappingInfo mapping(Method method, Class<?> type) { return getMappingForMethod(method, type); }
    }
}
