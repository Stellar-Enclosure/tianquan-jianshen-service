package top.egon.cola.platform.tianquan.jianshen.starter.permission;

import com.fasterxml.jackson.annotation.JsonProperty;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.databind.introspect.AnnotatedMember;
import jakarta.servlet.http.HttpServletRequest;
import top.egon.cola.platform.tianquan.jianshen.contract.permission.FieldCatalogSnapshot;
import top.egon.cola.platform.tianquan.jianshen.contract.permission.ResourceType;
import top.egon.cola.platform.tianquan.jianshen.starter.security.CurrentRbac3User;
import java.util.Arrays;
import java.util.Map;
import java.util.Set;
import java.util.TreeMap;

/** FIELD policy is metadata; input capability additionally requires a real, explicitly registered input DTO. */
public final class PermissionFieldCatalog {
    private final PermissionPolicyRegistry policies;
    private final CurrentEffectivePermissionView views;
    private final CurrentRbac3User users;

    public PermissionFieldCatalog(PermissionPolicyRegistry policies, CurrentEffectivePermissionView views, CurrentRbac3User users) {
        this.policies = policies; this.views = views; this.users = users;
    }

    public FieldCatalogSnapshot current(HttpServletRequest request, String hostResourceKey,
                                        ObjectMapper transportMapper, Set<Class<?>> actualInputDtoTypes) {
        return project(request, hostResourceKey, field -> actualInputDtoTypes.stream().anyMatch(type -> owns(type, field.target().get("dto"))
                && canBindProperty(transportMapper, type, field.target().get("property").toString())));
    }

    /** Resolves the actual first JSON reader for each registered input root and retains that mapper for nested values. */
    public FieldCatalogSnapshot currentForHttp(HttpServletRequest request, String hostResourceKey,
            java.util.List<org.springframework.http.converter.HttpMessageConverter<?>> converters,
            java.util.Collection<org.springframework.web.method.HandlerMethod> handlers,
            Set<String> ownedModelPackagePrefixes, Set<Class<?>> explicitInputs) {
        if (ownedModelPackagePrefixes == null || ownedModelPackagePrefixes.isEmpty() || ownedModelPackagePrefixes.size() > 32
                || ownedModelPackagePrefixes.stream().anyMatch(prefix -> prefix == null || !prefix.endsWith(".") || prefix.length() < 3)) {
            throw new IllegalArgumentException("finite owned input model packages are required");
        }
        var bindings = new java.util.HashMap<Class<?>, Set<ObjectMapper>>();
        var pending = new java.util.ArrayDeque<InputType>();
        for (var handler : handlers) {
            for (var parameter : handler.getMethodParameters()) {
                if (parameter.hasParameterAnnotation(org.springframework.web.bind.annotation.RequestBody.class)
                        || parameter.hasParameterAnnotation(org.springframework.web.bind.annotation.RequestPart.class)
                        || parameter.hasParameterAnnotation(org.springframework.web.bind.annotation.ModelAttribute.class)) {
                    addRoot(converters, parameter.getGenericParameterType(), handler.getBeanType(), pending);
                }
            }
        }
        for (Class<?> input : explicitInputs) addRoot(converters, input, null, pending);
        while (!pending.isEmpty()) {
            InputType next = pending.removeFirst();
            var type = next.type(); var mapper = next.mapper();
            if (type.isContainerType() || type.isReferenceType()) {
                var content = type.getContentType() == null ? type.getReferencedType() : type.getContentType();
                if (content != null) pending.add(new InputType(content, mapper));
                continue;
            }
            Class<?> raw = type.getRawClass();
            if (ownedModelPackagePrefixes.stream().noneMatch(prefix -> raw.getName().startsWith(prefix))
                    || !bindings.computeIfAbsent(raw, ignored -> new java.util.HashSet<>()).add(mapper)) continue;
            if (bindings.size() > 1024) throw new IllegalStateException("PERMISSION_INPUT_TYPES_LIMIT");
            for (var property : mapper.getDeserializationConfig().introspect(type).findProperties()) {
                if (canBindProperty(mapper, raw, property.getName())) pending.add(new InputType(property.getPrimaryType(), mapper));
            }
        }
        return project(request, hostResourceKey, field -> bindings.entrySet().stream().anyMatch(entry -> owns(entry.getKey(), field.target().get("dto"))
                && entry.getValue().stream().anyMatch(mapper -> canBindProperty(mapper, entry.getKey(), field.target().get("property").toString()))));
    }

    private static void addRoot(java.util.List<org.springframework.http.converter.HttpMessageConverter<?>> converters,
            java.lang.reflect.Type type, Class<?> context, java.util.ArrayDeque<InputType> pending) {
        var mediaType = org.springframework.http.MediaType.APPLICATION_JSON;
        for (var converter : converters) {
            boolean readable = converter instanceof org.springframework.http.converter.GenericHttpMessageConverter<?> generic
                    ? generic.canRead(type, context, mediaType)
                    : type instanceof Class<?> raw && converter.canRead(raw, mediaType);
            if (!readable) continue;
            if (converter instanceof org.springframework.http.converter.json.MappingJackson2HttpMessageConverter json) {
                var javaType = json.getObjectMapper().constructType(type);
                var registered = json.getObjectMappersForType(javaType.getRawClass());
                ObjectMapper mapper = registered.isEmpty() ? json.getObjectMapper() : registered.entrySet().stream()
                        .filter(entry -> entry.getKey().includes(mediaType)).map(Map.Entry::getValue).findFirst().orElse(null);
                if (mapper != null) pending.add(new InputType(mapper.constructType(type), mapper));
            }
            // The first readable converter owns the input; a later Jackson converter cannot claim it.
            return;
        }
    }

    private record InputType(com.fasterxml.jackson.databind.JavaType type, ObjectMapper mapper) { }

    private FieldCatalogSnapshot project(HttpServletRequest request, String hostResourceKey,
            java.util.function.Predicate<top.egon.cola.platform.tianquan.jianshen.contract.permission.PermissionManifest.ResourceDefinition> inputBinding) {
        if (!request.getParameterMap().keySet().equals(Set.of("keys"))) {
            throw new IllegalArgumentException("field catalog accepts only keys");
        }
        String[] requested = request.getParameterValues("keys");
        if (requested == null || requested.length == 0 || requested.length > 256
                || Arrays.stream(requested).anyMatch(key -> key == null || !key.matches("[A-Za-z0-9][A-Za-z0-9._:/-]{0,255}"))
                || Set.copyOf(Arrays.asList(requested)).size() != requested.length) {
            throw new IllegalArgumentException("field catalog requires 1..256 unique field keys");
        }
        var view = views.boundCurrent(request, hostResourceKey);
        var user = users.require();
        Map<String, FieldCatalogSnapshot.FieldDefinition> fields = new TreeMap<>();
        for (String key : requested) {
            final top.egon.cola.platform.tianquan.jianshen.contract.permission.PermissionManifest.ResourceDefinition field;
            try { field = policies.require(key, ResourceType.FIELD); }
            catch (IllegalStateException unknown) { throw new IllegalArgumentException("unknown field key", unknown); }
            policies.requireActive(user.snapshot(), key);
            boolean input = inputBinding.test(field);
            fields.put(key, new FieldCatalogSnapshot.FieldDefinition(field.access(), field.fieldPolicy(), input));
        }
        return new FieldCatalogSnapshot(view.catalogScope(), view.catalogVersion(), fields);
    }

    private static boolean owns(Class<?> input, Object owner) {
        for (Class<?> type = input; type != null && type != Object.class; type = type.getSuperclass()) {
            if (type.getCanonicalName() != null && type.getCanonicalName().equals(owner)) return true;
        }
        return false;
    }

    public static boolean canBindProperty(ObjectMapper mapper, Class<?> input, String name) {
        var bean = mapper.getDeserializationConfig().introspect(mapper.constructType(input));
        if (bean.getIgnoredPropertyNames().contains(name)) return false;
        for (var property : bean.findProperties()) {
            if (!name.equals(property.getName()) || !property.couldDeserialize()) continue;
            for (AnnotatedMember member : new AnnotatedMember[]{property.getPrimaryMember(), property.getField(), property.getGetter(),
                    property.getSetter(), property.getConstructorParameter()}) {
                if (member == null) continue;
                var annotation = member.getAnnotation(JsonProperty.class);
                if (annotation != null && annotation.access() == JsonProperty.Access.READ_ONLY) return false;
            }
            return true;
        }
        return false;
    }
}
