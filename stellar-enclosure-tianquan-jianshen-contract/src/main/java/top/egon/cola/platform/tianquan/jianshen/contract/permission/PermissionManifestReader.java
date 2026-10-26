package top.egon.cola.platform.tianquan.jianshen.contract.permission;

import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.function.Function;

/** Strict structural conversion after the host's bounded JSON parser has read an object. */
public final class PermissionManifestReader {

    public PermissionManifest read(Map<String, ?> input) {
        try {
            Map<String, Object> root = object(input, "manifest", "schemaVersion", "application", "producer",
                    "artifact", "permissionDefinitions", "permissionReferences", "resources", "resourceReferences", "messages");
            Map<String, Object> application = object(root.get("application"), "application", "businessCode", "applicationCode");
            Map<String, Object> producer = object(root.get("producer"), "producer", "id", "kind", "snapshotMode",
                    "ownedKeyPrefixes", "expectedModules", "scannedModules", "clearIntent");
            Map<String, Object> artifact = object(root.get("artifact"), "artifact", "repository", "commit", "buildId", "version");
            return new PermissionManifest(string(root, "schemaVersion"),
                    new PermissionManifest.Application(string(application, "businessCode"), string(application, "applicationCode")),
                    new PermissionManifest.Producer(string(producer, "id"),
                            enumeration(producer, "kind", PermissionManifest.ProducerKind.class),
                            enumeration(producer, "snapshotMode", PermissionManifest.SnapshotMode.class),
                            strings(producer.get("ownedKeyPrefixes"), "ownedKeyPrefixes"),
                            strings(producer.get("expectedModules"), "expectedModules"),
                            strings(producer.get("scannedModules"), "scannedModules"),
                            bool(producer, "clearIntent", false)),
                    new PermissionManifest.Artifact(string(artifact, "repository"), string(artifact, "commit"),
                            string(artifact, "buildId"), string(artifact, "version")),
                    items(root.get("permissionDefinitions"), "permissionDefinitions", this::permission),
                    strings(root.get("permissionReferences"), "permissionReferences"),
                    items(root.get("resources"), "resources", this::resource),
                    items(root.get("resourceReferences"), "resourceReferences", this::reference),
                    items(root.get("messages"), "messages", this::message));
        } catch (NullPointerException exception) {
            throw new IllegalArgumentException("manifest contains a missing required value", exception);
        }
    }

    public PermissionRequirement requirement(Object value) {
        Map<String, Object> object = object(value, "requirement", "mode", "codes", "allOf", "access");
        if (object.containsKey("access")) {
            if (object.size() != 1 || !"PUBLIC".equals(string(object, "access"))) {
                throw new IllegalArgumentException("invalid PUBLIC group");
            }
            return PermissionRequirement.publicAccess();
        }
        if (object.containsKey("allOf")) {
            if (object.size() != 1) throw new IllegalArgumentException("allOf cannot contain group properties");
            return PermissionRequirement.allOf(items(object.get("allOf"), "allOf", this::requirement));
        }
        return new PermissionRequirement(enumeration(object, "mode", PermissionMode.class),
                strings(object.get("codes"), "codes"));
    }

    private PermissionManifest.PermissionDefinition permission(Object value) {
        Map<String, Object> object = object(value, "permission", "code", "meaning", "i18n", "lifecycle");
        return new PermissionManifest.PermissionDefinition(string(object, "code"), string(object, "meaning"),
                i18n(object.get("i18n")), optionalEnum(object, "lifecycle", DefinitionLifecycle.class));
    }

    private PermissionManifest.ResourceDefinition resource(Object value) {
        Map<String, Object> object = object(value, "resource", "key", "type", "target", "access", "requirement",
                "fieldPolicy", "allowedPrincipals", "oauthScopes", "i18n", "lifecycle");
        return new PermissionManifest.ResourceDefinition(string(object, "key"),
                enumeration(object, "type", ResourceType.class), target(object.get("target")),
                optionalEnum(object, "access", ResourceAccess.class),
                optionalRequirement(object, "requirement"),
                object.get("fieldPolicy") == null ? null : fieldPolicy(object.get("fieldPolicy")),
                object.get("allowedPrincipals") == null ? null : strings(object.get("allowedPrincipals"), "allowedPrincipals")
                        .stream().map(PermissionManifest.PrincipalType::valueOf).toList(),
                object.get("oauthScopes") == null ? null : strings(object.get("oauthScopes"), "oauthScopes"),
                i18n(object.get("i18n")), optionalEnum(object, "lifecycle", DefinitionLifecycle.class));
    }

    private PermissionManifest.FieldPolicy fieldPolicy(Object value) {
        Map<String, Object> object = object(value, "fieldPolicy", "valueType", "plainRead", "maskedRead", "write", "masker");
        return new PermissionManifest.FieldPolicy(enumeration(object, "valueType", PermissionManifest.JsonFieldType.class),
                optionalRequirement(object, "plainRead"), optionalRequirement(object, "maskedRead"),
                optionalRequirement(object, "write"), optionalString(object, "masker"));
    }

    private PermissionRequirement optionalRequirement(Map<String, Object> object, String field) {
        return object.get(field) == null ? null : requirement(object.get(field));
    }

    private PermissionManifest.I18nReference i18n(Object value) {
        Map<String, Object> object = object(value, "i18n", "pageCode", "labelKey", "descriptionKey", "helpKey", "placeholderKey", "validationKey");
        return new PermissionManifest.I18nReference(string(object, "pageCode"), string(object, "labelKey"),
                optionalString(object, "descriptionKey"), optionalString(object, "helpKey"),
                optionalString(object, "placeholderKey"), optionalString(object, "validationKey"));
    }

    private PermissionManifest.ResourceReference reference(Object value) {
        Map<String, Object> object = object(value, "resourceReference", "key", "usage");
        return new PermissionManifest.ResourceReference(string(object, "key"), string(object, "usage"));
    }

    private PermissionManifest.Message message(Object value) {
        Map<String, Object> object = object(value, "message", "pageCode", "key", "defaultLocale", "defaults");
        return new PermissionManifest.Message(string(object, "pageCode"), string(object, "key"),
                string(object, "defaultLocale"), stringMap(object.get("defaults"), "defaults"));
    }

    private static Map<String, Object> object(Object value, String name, String... allowed) {
        if (!(value instanceof Map<?, ?> map)) throw new IllegalArgumentException(name + " must be an object");
        Set<String> names = Set.of(allowed);
        Map<String, Object> result = new LinkedHashMap<>();
        for (Map.Entry<?, ?> entry : map.entrySet()) {
            if (!(entry.getKey() instanceof String key) || !names.contains(key)) {
                throw new IllegalArgumentException(name + " contains an unknown property");
            }
            result.put(key, entry.getValue());
        }
        return result;
    }

    private static String string(Map<String, Object> object, String name) {
        if (!(object.get(name) instanceof String value)) throw new IllegalArgumentException(name + " must be a string");
        return value;
    }

    private static String optionalString(Map<String, Object> object, String name) {
        return object.get(name) == null ? null : string(object, name);
    }

    private static boolean bool(Map<String, Object> object, String name, boolean fallback) {
        if (!object.containsKey(name)) return fallback;
        if (!(object.get(name) instanceof Boolean value)) throw new IllegalArgumentException(name + " must be boolean");
        return value;
    }

    private static <T extends Enum<T>> T enumeration(Map<String, Object> object, String name, Class<T> type) {
        return Enum.valueOf(type, string(object, name));
    }

    private static <T extends Enum<T>> T optionalEnum(Map<String, Object> object, String name, Class<T> type) {
        return object.get(name) == null ? null : enumeration(object, name, type);
    }

    private static List<String> strings(Object value, String name) {
        return items(value, name, item -> {
            if (!(item instanceof String text)) throw new IllegalArgumentException(name + " contains a non-string");
            return text;
        });
    }

    private static <T> List<T> items(Object value, String name, Function<Object, T> converter) {
        if (!(value instanceof List<?> list) || list.size() > 20_000) {
            throw new IllegalArgumentException(name + " must be a bounded array");
        }
        List<T> result = new ArrayList<>(list.size());
        for (Object item : list) result.add(converter.apply(item));
        return result;
    }

    private static Map<String, String> stringMap(Object value, String name) {
        if (!(value instanceof Map<?, ?> map) || map.size() > 32) {
            throw new IllegalArgumentException(name + " must be a bounded string map");
        }
        Map<String, String> result = new LinkedHashMap<>();
        for (Map.Entry<?, ?> entry : map.entrySet()) {
            if (!(entry.getKey() instanceof String key) || !(entry.getValue() instanceof String text)) {
                throw new IllegalArgumentException(name + " must contain strings");
            }
            result.put(key, text);
        }
        return result;
    }

    private static Map<String, Object> target(Object value) {
        if (!(value instanceof Map<?, ?> map) || map.isEmpty() || map.size() > 32) {
            throw new IllegalArgumentException("target must be a bounded object");
        }
        Map<String, Object> result = new LinkedHashMap<>();
        for (Map.Entry<?, ?> entry : map.entrySet()) {
            if (!(entry.getKey() instanceof String key)) throw new IllegalArgumentException("invalid target key");
            result.put(key, entry.getValue());
        }
        return result;
    }
}
