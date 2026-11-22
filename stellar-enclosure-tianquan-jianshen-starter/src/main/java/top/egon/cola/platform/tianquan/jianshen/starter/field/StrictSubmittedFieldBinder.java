package top.egon.cola.platform.tianquan.jianshen.starter.field;

import com.fasterxml.jackson.annotation.JsonProperty;
import com.fasterxml.jackson.core.JsonParser;
import com.fasterxml.jackson.core.StreamReadConstraints;
import com.fasterxml.jackson.databind.BeanDescription;
import com.fasterxml.jackson.databind.DeserializationFeature;
import com.fasterxml.jackson.databind.JavaType;
import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.MapperFeature;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.databind.SerializationFeature;
import com.fasterxml.jackson.databind.cfg.CoercionAction;
import com.fasterxml.jackson.databind.cfg.CoercionInputShape;
import com.fasterxml.jackson.databind.introspect.AnnotatedMember;
import com.fasterxml.jackson.databind.introspect.BeanPropertyDefinition;
import com.fasterxml.jackson.databind.type.LogicalType;
import org.springframework.web.context.request.RequestAttributes;
import org.springframework.web.context.request.RequestContextHolder;
import top.egon.cola.platform.tianquan.jianshen.contract.permission.ResourceType;
import top.egon.cola.platform.tianquan.jianshen.contract.permission.annotation.FieldPermissions;
import top.egon.cola.platform.tianquan.jianshen.contract.permission.annotation.PermissionResource;
import top.egon.cola.platform.tianquan.jianshen.starter.permission.PermissionPolicyRegistry;

import java.io.IOException;
import java.io.InputStream;
import java.lang.reflect.AnnotatedElement;
import java.lang.reflect.RecordComponent;
import java.lang.reflect.Type;
import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Map;
import java.util.Objects;
import java.util.Set;
import java.util.concurrent.ConcurrentHashMap;

/**
 * Bounded strict JSON reader that automatically captures {@link SubmittedFieldSet} trees
 * against DTO bindings and enforces {@link PermissionFieldBindingGuard} before handler invocation.
 */
public final class StrictSubmittedFieldBinder {

    private static final String REQUEST_VERIFIED_ATTRIBUTE = StrictSubmittedFieldBinder.class.getName() + ".VERIFIED";
    private static final int DEFAULT_MAX_BYTES = 16 * 1024 * 1024 + 1024 * 1024;
    private static final int DEFAULT_MAX_DEPTH = 16;

    private final ObjectMapper baseMapper;
    private final ObjectMapper defaultStrictMapper;
    private final PermissionFieldBindingGuard fieldWrites;
    private final PermissionPolicyRegistry registry;
    private final Map<Class<?>, Boolean> managedDtoCache = new ConcurrentHashMap<>();

    public StrictSubmittedFieldBinder(ObjectMapper baseMapper, PermissionFieldBindingGuard fieldWrites) {
        this(baseMapper, fieldWrites, null);
    }

    public StrictSubmittedFieldBinder(
            ObjectMapper baseMapper,
            PermissionFieldBindingGuard fieldWrites,
            PermissionPolicyRegistry registry) {
        this.baseMapper = Objects.requireNonNull(baseMapper, "baseMapper");
        this.fieldWrites = Objects.requireNonNull(fieldWrites, "fieldWrites");
        this.registry = registry;
        this.defaultStrictMapper = strictMapper(baseMapper, DEFAULT_MAX_BYTES, DEFAULT_MAX_DEPTH);
    }

    /** Reads at most {@code maxBytes} from the body stream, failing closed on overflow. */
    public byte[] readBounded(InputStream body, int maxBytes) throws IOException {
        if (maxBytes <= 0) {
            throw new IllegalArgumentException("maxBytes must be positive");
        }
        byte[] bytes = Objects.requireNonNull(body, "body").readNBytes(maxBytes + 1);
        if (bytes.length > maxBytes) {
            throw new IllegalArgumentException("request payload exceeds byte limit");
        }
        return bytes;
    }

    /**
     * Parses raw JSON strictly (no scalar coercion, no duplicate keys, no unknown fields, no trailing tokens),
     * enforces {@code requiredFields} and {@link PermissionFieldBindingGuard} across the DTO graph,
     * and validates typed deserialization before the MVC converter runs.
     */
    public void validateAndAuthorize(byte[] rawBytes, Type targetType, StrictFieldBinding binding) {
        Objects.requireNonNull(rawBytes, "rawBytes");
        Objects.requireNonNull(targetType, "targetType");
        Objects.requireNonNull(binding, "binding");
        if (rawBytes.length > binding.maxBytes()) {
            throw new IllegalArgumentException("request payload exceeds byte limit");
        }
        ObjectMapper strict = mapperFor(binding);
        JsonNode root = readRootObject(strict, rawBytes);
        JavaType javaType = strict.constructType(targetType);
        inspectNode(root, javaType, strict, Set.of(binding.requiredFields()));
        try {
            strict.readValue(rawBytes, javaType);
        } catch (IOException failure) {
            throw new IllegalArgumentException("invalid JSON payload", failure);
        }
    }

    static void markRequestVerified() {
        RequestAttributes attributes = RequestContextHolder.getRequestAttributes();
        if (attributes != null) {
            attributes.setAttribute(REQUEST_VERIFIED_ATTRIBUTE, Boolean.TRUE, RequestAttributes.SCOPE_REQUEST);
        }
    }

    static void clearRequestVerified() {
        RequestAttributes attributes = RequestContextHolder.getRequestAttributes();
        if (attributes != null) {
            attributes.removeAttribute(REQUEST_VERIFIED_ATTRIBUTE, RequestAttributes.SCOPE_REQUEST);
        }
    }

    static boolean isRequestVerified() {
        RequestAttributes attributes = RequestContextHolder.getRequestAttributes();
        return attributes != null
                && Boolean.TRUE.equals(attributes.getAttribute(REQUEST_VERIFIED_ATTRIBUTE, RequestAttributes.SCOPE_REQUEST));
    }

    private ObjectMapper mapperFor(StrictFieldBinding binding) {
        if (binding.maxBytes() == DEFAULT_MAX_BYTES && binding.maxNestingDepth() == DEFAULT_MAX_DEPTH) {
            return defaultStrictMapper;
        }
        return strictMapper(baseMapper, binding.maxBytes(), binding.maxNestingDepth());
    }

    private static ObjectMapper strictMapper(ObjectMapper source, int maxBytes, int maxNestingDepth) {
        ObjectMapper strict = source.copy()
                .enable(DeserializationFeature.FAIL_ON_UNKNOWN_PROPERTIES)
                .enable(DeserializationFeature.FAIL_ON_TRAILING_TOKENS)
                .disable(MapperFeature.ALLOW_COERCION_OF_SCALARS)
                .enable(JsonParser.Feature.STRICT_DUPLICATE_DETECTION)
                .disable(SerializationFeature.WRITE_DATES_AS_TIMESTAMPS);
        strict.coercionConfigFor(LogicalType.Textual)
                .setCoercion(CoercionInputShape.Integer, CoercionAction.Fail)
                .setCoercion(CoercionInputShape.Float, CoercionAction.Fail)
                .setCoercion(CoercionInputShape.Boolean, CoercionAction.Fail);
        strict.getFactory().setStreamReadConstraints(StreamReadConstraints.builder()
                .maxNestingDepth(maxNestingDepth)
                .maxStringLength(maxBytes)
                .build());
        return strict;
    }

    private static JsonNode readRootObject(ObjectMapper strict, byte[] rawBytes) {
        JsonNode root;
        try (JsonParser parser = strict.createParser(rawBytes)) {
            root = strict.readValue(parser, JsonNode.class);
            if (root == null || parser.nextToken() != null) {
                throw new IllegalArgumentException("invalid JSON payload");
            }
        } catch (IOException failure) {
            throw new IllegalArgumentException("invalid JSON payload", failure);
        }
        if (!root.isObject()) {
            throw new IllegalArgumentException("request body must be a JSON object");
        }
        return root;
    }

    private void inspectNode(JsonNode node, JavaType type, ObjectMapper strict, Set<String> requiredFields) {
        if (node == null || node.isNull() || type == null) {
            return;
        }
        if (type.isReferenceType()) {
            inspectNode(node, type.getReferencedType(), strict, requiredFields);
            return;
        }
        if (type.isContainerType()) {
            if (type.isMapLikeType() && node.isObject()) {
                JavaType contentType = type.getContentType();
                node.fields().forEachRemaining(entry -> inspectNode(entry.getValue(), contentType, strict, Set.of()));
            } else if ((type.isCollectionLikeType() || type.isArrayType()) && node.isArray()) {
                JavaType contentType = type.getContentType();
                for (JsonNode item : node) {
                    inspectNode(item, contentType, strict, Set.of());
                }
            }
            return;
        }
        Class<?> rawClass = type.getRawClass();
        if (isScalarOrOpaque(rawClass)) {
            return;
        }
        BeanDescription bean = strict.getDeserializationConfig().introspect(type);
        List<BeanPropertyDefinition> properties = bean.findProperties();
        if (properties.isEmpty()) {
            return;
        }
        if (!node.isObject()) {
            throw new IllegalArgumentException("expected JSON object for " + rawClass.getSimpleName());
        }
        Map<String, BeanPropertyDefinition> lookup = propertyLookup(properties, strict);
        Set<String> submitted = new LinkedHashSet<>();
        Set<String> writable = new LinkedHashSet<>();
        List<ChildInspection> children = new ArrayList<>();
        var fields = node.fields();
        while (fields.hasNext()) {
            var entry = fields.next();
            String rawName = entry.getKey();
            BeanPropertyDefinition property = lookup.get(rawName);
            if (property == null) {
                throw new IllegalArgumentException("unknown field: " + rawName);
            }
            if (!submitted.add(property.getName())) {
                throw new IllegalArgumentException("duplicate field: " + rawName);
            }
            if (!isReadOnly(property)) {
                writable.add(property.getName());
            }
            children.add(new ChildInspection(entry.getValue(), property.getPrimaryType()));
        }
        for (String required : requiredFields) {
            if (!submitted.contains(required)) {
                throw new IllegalArgumentException("missing required field: " + required);
            }
        }
        if (isManagedFieldDto(rawClass)) {
            fieldWrites.require(rawClass, new SubmittedFieldSet(submitted), writable);
        }
        for (ChildInspection child : children) {
            inspectNode(child.node(), child.type(), strict, Set.of());
        }
    }

    private Map<String, BeanPropertyDefinition> propertyLookup(
            List<BeanPropertyDefinition> properties, ObjectMapper strict) {
        Map<String, BeanPropertyDefinition> lookup = new LinkedHashMap<>();
        var introspector = strict.getDeserializationConfig().getAnnotationIntrospector();
        for (BeanPropertyDefinition property : properties) {
            lookup.put(property.getName(), property);
            if (introspector != null && property.getPrimaryMember() != null) {
                var aliases = introspector.findPropertyAliases(property.getPrimaryMember());
                if (aliases != null) {
                    for (var alias : aliases) {
                        lookup.putIfAbsent(alias.getSimpleName(), property);
                    }
                }
            }
        }
        return lookup;
    }

    private boolean isManagedFieldDto(Class<?> rawClass) {
        if (registry != null && !registry.fields(rawClass).isEmpty()) {
            return true;
        }
        return managedDtoCache.computeIfAbsent(rawClass, StrictSubmittedFieldBinder::hasDeclaredFieldAnnotations);
    }

    private static boolean hasDeclaredFieldAnnotations(Class<?> type) {
        for (Class<?> current = type; current != null && current != Object.class; current = current.getSuperclass()) {
            if (current.isRecord()) {
                for (RecordComponent component : current.getRecordComponents()) {
                    if (hasFieldAnnotation(component)) {
                        return true;
                    }
                }
            }
            for (var field : current.getDeclaredFields()) {
                if (hasFieldAnnotation(field)) {
                    return true;
                }
            }
            for (var method : current.getDeclaredMethods()) {
                if (hasFieldAnnotation(method)) {
                    return true;
                }
            }
        }
        return false;
    }

    private static boolean hasFieldAnnotation(AnnotatedElement element) {
        if (element.isAnnotationPresent(FieldPermissions.class)) {
            return true;
        }
        PermissionResource resource = element.getAnnotation(PermissionResource.class);
        return resource != null && resource.type() == ResourceType.FIELD;
    }

    private static boolean isReadOnly(BeanPropertyDefinition property) {
        for (AnnotatedMember member : new AnnotatedMember[]{
                property.getPrimaryMember(), property.getField(), property.getGetter(),
                property.getSetter(), property.getConstructorParameter()}) {
            if (member == null) {
                continue;
            }
            JsonProperty annotation = member.getAnnotation(JsonProperty.class);
            if (annotation != null && annotation.access() == JsonProperty.Access.READ_ONLY) {
                return true;
            }
        }
        return !property.couldDeserialize();
    }

    private static boolean isScalarOrOpaque(Class<?> type) {
        if (type.isPrimitive() || type.isEnum() || JsonNode.class.isAssignableFrom(type)) {
            return true;
        }
        String name = type.getName();
        return name.startsWith("java.") || name.startsWith("javax.") || name.startsWith("jakarta.");
    }

    private record ChildInspection(JsonNode node, JavaType type) { }
}
