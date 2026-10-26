package top.egon.cola.platform.tianquan.jianshen.admin.registration.catalog.domain.convertor;

import com.fasterxml.jackson.core.JsonParser;
import com.fasterxml.jackson.core.StreamReadConstraints;
import com.fasterxml.jackson.core.type.TypeReference;
import com.fasterxml.jackson.databind.DeserializationFeature;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.databind.SerializationFeature;
import org.springframework.beans.factory.annotation.Qualifier;
import org.springframework.stereotype.Component;
import top.egon.cola.platform.tianquan.jianshen.contract.permission.CanonicalJson;
import top.egon.cola.platform.tianquan.jianshen.contract.permission.CatalogScope;
import top.egon.cola.platform.tianquan.jianshen.contract.permission.ManifestDigests;
import top.egon.cola.platform.tianquan.jianshen.contract.permission.ManifestRegistrationRequest;
import top.egon.cola.platform.tianquan.jianshen.contract.permission.PermissionManifest;
import top.egon.cola.platform.tianquan.jianshen.contract.permission.PermissionManifestCanonicalizer;
import top.egon.cola.platform.tianquan.jianshen.contract.permission.PermissionManifestReader;

import java.io.IOException;
import java.io.InputStream;
import java.nio.charset.StandardCharsets;
import java.util.List;
import java.util.Map;
import java.util.Set;

/** Bounded strict JSON at the registry boundary; all manifest semantics remain in RC. */
@Component
public final class PermissionCatalogJson {

    public static final int MAX_ENVELOPE_BYTES = PermissionManifest.MAX_BYTES + 1024 * 1024;
    private static final TypeReference<Map<String, Object>> OBJECT = new TypeReference<>() { };
    private static final TypeReference<List<String>> STRINGS = new TypeReference<>() { };
    private final ObjectMapper mapper;

    public PermissionCatalogJson(@Qualifier("jacksonObjectMapper") ObjectMapper mapper) {
        this.mapper = mapper.copy().enable(DeserializationFeature.FAIL_ON_UNKNOWN_PROPERTIES)
                .enable(DeserializationFeature.FAIL_ON_TRAILING_TOKENS)
                .disable(com.fasterxml.jackson.databind.MapperFeature.ALLOW_COERCION_OF_SCALARS)
                .enable(JsonParser.Feature.STRICT_DUPLICATE_DETECTION)
                .disable(SerializationFeature.WRITE_DATES_AS_TIMESTAMPS);
        this.mapper.coercionConfigFor(com.fasterxml.jackson.databind.type.LogicalType.Textual)
                .setCoercion(com.fasterxml.jackson.databind.cfg.CoercionInputShape.Integer, com.fasterxml.jackson.databind.cfg.CoercionAction.Fail)
                .setCoercion(com.fasterxml.jackson.databind.cfg.CoercionInputShape.Float, com.fasterxml.jackson.databind.cfg.CoercionAction.Fail)
                .setCoercion(com.fasterxml.jackson.databind.cfg.CoercionInputShape.Boolean, com.fasterxml.jackson.databind.cfg.CoercionAction.Fail);
        this.mapper.getFactory().setStreamReadConstraints(StreamReadConstraints.builder()
                .maxNestingDepth(16).maxStringLength(PermissionManifest.MAX_BYTES).build());
    }

    public Map<String, Object> readObject(InputStream input) throws IOException {
        byte[] bytes = input.readNBytes(MAX_ENVELOPE_BYTES + 1);
        if (bytes.length > MAX_ENVELOPE_BYTES) throw new IllegalArgumentException("registration payload exceeds byte limit");
        return mapper.readValue(bytes, OBJECT);
    }

    public Map<String, Object> readObject(String value) {
        if (value == null || value.getBytes(StandardCharsets.UTF_8).length > MAX_ENVELOPE_BYTES * 2) {
            throw new IllegalArgumentException("stored catalog payload exceeds storage limit");
        }
        try {
            return mapper.readValue(value, OBJECT);
        } catch (IOException failure) {
            throw new IllegalArgumentException("invalid catalog JSON", failure);
        }
    }

    public PermissionManifest manifest(String value) {
        return new PermissionManifestReader().read(readObject(value));
    }

    public ManifestRegistrationRequest.Plan plan(Map<String, Object> value) {
        fields(value, "target", "manifest", "expectedProducerRevision", "expectedActiveRevision");
        return new ManifestRegistrationRequest.Plan(scope(object(value, "target")),
                new PermissionManifestReader().read(object(value, "manifest")),
                text(value, "expectedProducerRevision"), text(value, "expectedActiveRevision"));
    }

    public ManifestRegistrationRequest.Apply apply(Map<String, Object> value) {
        fields(value, "target", "producerId", "planId", "operationId", "digests", "expectedProducerRevision", "expectedActiveRevision");
        Map<String, Object> digests = object(value, "digests");
        fields(digests, "policyDigest", "metadataDigest", "manifestDigest");
        return new ManifestRegistrationRequest.Apply(scope(object(value, "target")), text(value, "producerId"),
                text(value, "planId"), text(value, "operationId"),
                new ManifestDigests(text(digests, "policyDigest"), text(digests, "metadataDigest"), text(digests, "manifestDigest")),
                text(value, "expectedProducerRevision"), text(value, "expectedActiveRevision"));
    }

    public CatalogScope scope(Map<String, Object> value) {
        fields(value, "catalogScopeId", "tenantId", "businessCode", "applicationCode", "namespaceCode", "environment");
        return new CatalogScope(text(value, "catalogScopeId"), text(value, "tenantId"), text(value, "businessCode"),
                text(value, "applicationCode"), text(value, "namespaceCode"), text(value, "environment"));
    }

    public List<String> strings(String json) {
        try {
            return List.copyOf(mapper.readValue(json, STRINGS));
        } catch (IOException failure) {
            throw new IllegalArgumentException("invalid catalog string list", failure);
        }
    }

    public <T> T read(String json, Class<T> type) {
        try {
            return mapper.readValue(json, type);
        } catch (IOException failure) {
            throw new IllegalArgumentException("invalid catalog record", failure);
        }
    }

    public String write(Object value) {
        if (value instanceof PermissionManifest manifest) return new PermissionManifestCanonicalizer().canonicalize(manifest);
        return CanonicalJson.write(mapper.convertValue(value, Object.class));
    }

    public static void fields(Map<String, Object> value, String... names) {
        if (value == null || !value.keySet().equals(Set.of(names))) {
            throw new IllegalArgumentException("catalog object has unknown or missing fields");
        }
    }

    public static String text(Map<String, Object> value, String key) {
        if (!(value.get(key) instanceof String text)) throw new IllegalArgumentException(key + " must be a string");
        return text;
    }

    public static Map<String, Object> object(Map<String, Object> value, String key) {
        if (!(value.get(key) instanceof Map<?, ?> object)) throw new IllegalArgumentException(key + " must be an object");
        Map<String, Object> result = new java.util.LinkedHashMap<>();
        object.forEach((name, item) -> {
            if (!(name instanceof String text)) throw new IllegalArgumentException("JSON field names must be strings");
            result.put(text, item);
        });
        return result;
    }
}
