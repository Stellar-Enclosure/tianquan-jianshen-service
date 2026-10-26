package top.egon.cola.platform.tianquan.jianshen.contract.permission;

import java.util.ArrayList;
import java.util.Comparator;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.TreeMap;

/** The same projections are used by generators, registry and metadata import. */
public final class PermissionManifestCanonicalizer {

    public ManifestDigests digests(PermissionManifest manifest) {
        Map<String, Object> complete = toMap(manifest);
        Map<String, Object> policy = new LinkedHashMap<>();
        policy.put("schemaVersion", manifest.schemaVersion());
        policy.put("application", complete.get("application"));
        policy.put("permissionDefinitions", manifest.permissionDefinitions().stream()
                .map(definition -> Map.of("code", definition.code(), "meaning", definition.meaning(),
                        "lifecycle", definition.lifecycle().name())).toList());
        policy.put("permissionReferences", manifest.permissionReferences());
        policy.put("resources", manifest.resources().stream().map(resource -> {
            Map<String, Object> value = resourceMap(resource);
            value.remove("i18n");
            return value;
        }).toList());
        policy.put("resourceReferences", complete.get("resourceReferences"));

        Map<String, Object> metadata = new LinkedHashMap<>();
        metadata.put("schemaVersion", manifest.schemaVersion());
        metadata.put("application", complete.get("application"));
        metadata.put("permissions", manifest.permissionDefinitions().stream()
                .map(definition -> Map.of("code", definition.code(), "i18n", i18nMap(definition.i18n()))).toList());
        metadata.put("resources", manifest.resources().stream()
                .map(resource -> Map.of("key", resource.key(), "i18n", i18nMap(resource.i18n()))).toList());
        metadata.put("messages", complete.get("messages"));
        return new ManifestDigests(CanonicalJson.digest(policy), CanonicalJson.digest(metadata),
                CanonicalJson.digest(complete));
    }

    public String canonicalize(PermissionManifest manifest) {
        return CanonicalJson.write(toMap(manifest));
    }

    public Map<String, Object> toMap(PermissionManifest manifest) {
        Map<String, Object> result = new LinkedHashMap<>();
        result.put("schemaVersion", manifest.schemaVersion());
        result.put("application", Map.of("businessCode", manifest.application().businessCode(),
                "applicationCode", manifest.application().applicationCode()));
        PermissionManifest.Producer producer = manifest.producer();
        result.put("producer", Map.of("id", producer.id(), "kind", producer.kind().name(),
                "snapshotMode", producer.snapshotMode().name(), "ownedKeyPrefixes", producer.ownedKeyPrefixes(),
                "expectedModules", producer.expectedModules(), "scannedModules", producer.scannedModules(),
                "clearIntent", producer.clearIntent()));
        PermissionManifest.Artifact artifact = manifest.artifact();
        result.put("artifact", Map.of("repository", artifact.repository(), "commit", artifact.commit(),
                "buildId", artifact.buildId(), "version", artifact.version()));
        result.put("permissionDefinitions", manifest.permissionDefinitions().stream().map(definition -> Map.of(
                "code", definition.code(), "meaning", definition.meaning(), "i18n", i18nMap(definition.i18n()),
                "lifecycle", definition.lifecycle().name())).toList());
        result.put("permissionReferences", manifest.permissionReferences());
        result.put("resources", manifest.resources().stream().map(this::resourceMap).toList());
        result.put("resourceReferences", manifest.resourceReferences().stream()
                .map(reference -> Map.of("key", reference.key(), "usage", reference.usage())).toList());
        result.put("messages", manifest.messages().stream().map(this::messageMap).toList());
        return result;
    }

    public Map<String, Object> resourceMap(PermissionManifest.ResourceDefinition resource) {
        Map<String, Object> result = new LinkedHashMap<>();
        result.put("key", resource.key());
        result.put("type", resource.type().name());
        result.put("target", resource.target());
        result.put("access", resource.access().name());
        result.put("lifecycle", resource.lifecycle().name());
        result.put("allowedPrincipals", resource.allowedPrincipals().stream().map(Enum::name).sorted().toList());
        result.put("oauthScopes", resource.oauthScopes());
        result.put("i18n", i18nMap(resource.i18n()));
        if (resource.requirement() != null) result.put("requirement", requirementMap(resource.requirement()));
        if (resource.fieldPolicy() != null) {
            PermissionManifest.FieldPolicy policy = resource.fieldPolicy();
            Map<String, Object> field = new LinkedHashMap<>();
            field.put("valueType", policy.valueType().name());
            if (policy.plainRead() != null) field.put("plainRead", requirementMap(policy.plainRead()));
            if (policy.maskedRead() != null) field.put("maskedRead", requirementMap(policy.maskedRead()));
            if (policy.write() != null) field.put("write", requirementMap(policy.write()));
            if (policy.masker() != null) field.put("masker", policy.masker());
            result.put("fieldPolicy", field);
        }
        return result;
    }

    public Map<String, Object> requirementMap(PermissionRequirement requirement) {
        if (requirement.access() == ResourceAccess.PUBLIC) return Map.of("access", "PUBLIC");
        if (requirement.allOf().isEmpty()) {
            return Map.of("mode", requirement.mode().name(), "codes", requirement.codes());
        }
        List<Map<String, Object>> groups = new ArrayList<>(requirement.allOf().stream()
                .map(this::requirementMap).toList());
        groups.sort(Comparator.comparing(CanonicalJson::write));
        groups = groups.stream().distinct().toList();
        return groups.size() == 1 ? groups.getFirst() : Map.of("allOf", groups);
    }

    public Map<String, Object> i18nMap(PermissionManifest.I18nReference reference) {
        Map<String, Object> result = new LinkedHashMap<>();
        result.put("pageCode", reference.pageCode());
        result.put("labelKey", reference.labelKey());
        if (reference.descriptionKey() != null) result.put("descriptionKey", reference.descriptionKey());
        if (reference.helpKey() != null) result.put("helpKey", reference.helpKey());
        if (reference.placeholderKey() != null) result.put("placeholderKey", reference.placeholderKey());
        if (reference.validationKey() != null) result.put("validationKey", reference.validationKey());
        return result;
    }

    public Map<String, Object> messageMap(PermissionManifest.Message message) {
        return Map.of("pageCode", message.pageCode(), "key", message.key(),
                "defaultLocale", message.defaultLocale(), "defaults", new TreeMap<>(message.defaults()));
    }
}
