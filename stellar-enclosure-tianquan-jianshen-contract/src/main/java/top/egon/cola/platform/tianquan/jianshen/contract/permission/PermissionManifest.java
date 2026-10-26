package top.egon.cola.platform.tianquan.jianshen.contract.permission;

import com.fasterxml.jackson.annotation.JsonInclude;

import java.util.HashSet;
import java.util.ArrayList;
import java.util.List;
import java.util.Map;
import java.util.Objects;
import java.util.Set;
import java.util.TreeMap;

/** The source-owned permission contract. Environment and centre IDs belong to the envelope. */
@JsonInclude(JsonInclude.Include.NON_NULL)
public record PermissionManifest(
        String schemaVersion,
        Application application,
        Producer producer,
        Artifact artifact,
        List<PermissionDefinition> permissionDefinitions,
        List<String> permissionReferences,
        List<ResourceDefinition> resources,
        List<ResourceReference> resourceReferences,
        List<Message> messages
) {

    public static final String SCHEMA_VERSION = "1.0";
    public static final int MAX_BYTES = 16 * 1024 * 1024;

    public PermissionManifest {
        if (!SCHEMA_VERSION.equals(schemaVersion)) {
            throw new IllegalArgumentException("unsupported permission manifest schemaVersion");
        }
        Objects.requireNonNull(application, "application");
        Objects.requireNonNull(producer, "producer");
        Objects.requireNonNull(artifact, "artifact");
        permissionDefinitions = ManifestChecks.sortedUnique(permissionDefinitions,
                "permissionDefinitions", 10_000, PermissionDefinition::code);
        permissionReferences = ManifestChecks.identifiers(permissionReferences,
                "permissionReferences", 10_000, 128);
        resources = ManifestChecks.sortedUnique(resources, "resources", 10_000, ResourceDefinition::key);
        resourceReferences = ManifestChecks.sortedUnique(resourceReferences,
                "resourceReferences", 10_000, reference -> reference.key() + ':' + reference.usage());
        messages = ManifestChecks.sortedUnique(messages, "messages", 20_000,
                message -> message.pageCode() + '/' + message.key());

        Set<String> knownCodes = new HashSet<>(permissionReferences);
        for (PermissionDefinition definition : permissionDefinitions) {
            if (!knownCodes.add(definition.code())) {
                throw new IllegalArgumentException("a permission must be defined or referenced, not both");
            }
        }
        for (ResourceDefinition resource : resources) {
            if (producer.ownedKeyPrefixes().stream().noneMatch(resource.key()::startsWith)) {
                throw new IllegalArgumentException("resource key is outside producer prefixes");
            }
            requireDeclaredCodes(resource.requirement(), knownCodes);
            if (resource.fieldPolicy() != null) {
                requireDeclaredCodes(resource.fieldPolicy().plainRead(), knownCodes);
                requireDeclaredCodes(resource.fieldPolicy().maskedRead(), knownCodes);
                requireDeclaredCodes(resource.fieldPolicy().write(), knownCodes);
            }
            if (CanonicalJson.write(new PermissionManifestCanonicalizer().resourceMap(resource))
                    .getBytes(java.nio.charset.StandardCharsets.UTF_8).length > 256 * 1024) {
                throw new IllegalArgumentException("resource policy exceeds its byte limit");
            }
        }
        Set<String> ownedKeys = new HashSet<>();
        resources.forEach(resource -> ownedKeys.add(resource.key()));
        if (resourceReferences.stream().anyMatch(reference -> ownedKeys.contains(reference.key()))) {
            throw new IllegalArgumentException("a resource cannot be owned and referenced by the same producer");
        }
        boolean empty = resources.isEmpty() && permissionDefinitions.isEmpty() && messages.isEmpty();
        if (producer.snapshotMode() == SnapshotMode.FULL && empty && !producer.clearIntent()) {
            throw new IllegalArgumentException("empty FULL manifests require an explicit clear intent");
        }
        if (producer.clearIntent() && (!empty || producer.snapshotMode() != SnapshotMode.FULL)) {
            throw new IllegalArgumentException("clearIntent requires an empty complete manifest");
        }
    }

    private static void requireDeclaredCodes(PermissionRequirement requirement, Set<String> declared) {
        if (requirement != null && requirement.groups().stream()
                .anyMatch(group -> !declared.containsAll(group.codes()))) {
            throw new IllegalArgumentException("permission expression contains an undeclared reference");
        }
    }

    public enum ProducerKind { JAVA, REACT_TYPESCRIPT }
    public enum SnapshotMode { FULL, PARTIAL }
    public enum PrincipalType { USER, SERVICE }
    public enum JsonFieldType { STRING, NUMBER, BOOLEAN, OBJECT, ARRAY }

    public record Application(String businessCode, String applicationCode) {
        public Application {
            businessCode = ManifestChecks.identifier(businessCode, "businessCode", 128);
            applicationCode = ManifestChecks.identifier(applicationCode, "applicationCode", 128);
        }
    }

    public record Producer(
            String id,
            ProducerKind kind,
            SnapshotMode snapshotMode,
            List<String> ownedKeyPrefixes,
            List<String> expectedModules,
            List<String> scannedModules,
            boolean clearIntent
    ) {
        public Producer {
            id = ManifestChecks.identifier(id, "producer.id", 128);
            Objects.requireNonNull(kind, "producer.kind");
            Objects.requireNonNull(snapshotMode, "producer.snapshotMode");
            ownedKeyPrefixes = ManifestChecks.identifiers(ownedKeyPrefixes, "ownedKeyPrefixes", 128, 200);
            expectedModules = ManifestChecks.identifiers(expectedModules, "expectedModules", 256, 200);
            scannedModules = ManifestChecks.identifiers(scannedModules, "scannedModules", 256, 200);
            if (expectedModules.isEmpty() || scannedModules.isEmpty()
                    || !expectedModules.containsAll(scannedModules)
                    || (snapshotMode == SnapshotMode.FULL && !expectedModules.equals(scannedModules))) {
                throw new IllegalArgumentException("scan completeness does not match expected modules");
            }
        }
    }

    public record Artifact(String repository, String commit, String buildId, String version) {
        public Artifact {
            repository = ManifestChecks.text(repository, "artifact.repository", 256);
            if (commit == null || !commit.matches("[0-9a-f]{40}|[0-9a-f]{64}")) {
                throw new IllegalArgumentException("artifact.commit must be a full lower-case Git object ID");
            }
            buildId = ManifestChecks.text(buildId, "artifact.buildId", 256);
            version = ManifestChecks.text(version, "artifact.version", 128);
        }
    }

    @JsonInclude(JsonInclude.Include.NON_NULL)
    public record I18nReference(
            String pageCode,
            String labelKey,
            String descriptionKey,
            String helpKey,
            String placeholderKey,
            String validationKey
    ) {
        public I18nReference {
            pageCode = I18nSourceRules.key(pageCode);
            labelKey = I18nSourceRules.key(labelKey);
            for (String key : new String[]{descriptionKey, helpKey, placeholderKey, validationKey}) {
                if (key != null) {
                    I18nSourceRules.key(key);
                }
            }
        }

        public I18nReference(String pageCode, String labelKey) {
            this(pageCode, labelKey, null, null, null, null);
        }

        public List<String> keys() {
            return java.util.stream.Stream.of(labelKey, descriptionKey, helpKey, placeholderKey, validationKey)
                    .filter(Objects::nonNull).distinct().sorted().toList();
        }
    }

    public record PermissionDefinition(
            String code,
            String meaning,
            I18nReference i18n,
            DefinitionLifecycle lifecycle
    ) {
        public PermissionDefinition {
            code = ManifestChecks.identifier(code, "permission.code", 128);
            meaning = ManifestChecks.text(meaning, "permission.meaning", 1024);
            Objects.requireNonNull(i18n, "permission.i18n");
            lifecycle = lifecycle == null ? DefinitionLifecycle.ACTIVE : lifecycle;
        }
    }

    @JsonInclude(JsonInclude.Include.NON_NULL)
    public record FieldPolicy(
            JsonFieldType valueType,
            PermissionRequirement plainRead,
            PermissionRequirement maskedRead,
            PermissionRequirement write,
            String masker
    ) {
        public FieldPolicy {
            Objects.requireNonNull(valueType, "fieldPolicy.valueType");
            if (maskedRead == null && masker != null) {
                throw new IllegalArgumentException("masker requires a maskedRead rule");
            }
            if (maskedRead != null && (masker == null || valueType != JsonFieldType.STRING
                    || !Set.of("FIXED", "EMAIL", "PHONE", "BANK_ACCOUNT").contains(masker))) {
                throw new IllegalArgumentException("masker does not preserve the declared JSON type");
            }
        }
    }

    @JsonInclude(JsonInclude.Include.NON_NULL)
    public record ResourceDefinition(
            String key,
            ResourceType type,
            Map<String, Object> target,
            ResourceAccess access,
            PermissionRequirement requirement,
            FieldPolicy fieldPolicy,
            List<PrincipalType> allowedPrincipals,
            List<String> oauthScopes,
            I18nReference i18n,
            DefinitionLifecycle lifecycle
    ) {
        public ResourceDefinition {
            key = ManifestChecks.identifier(key, "resource.key", 200);
            Objects.requireNonNull(type, "resource.type");
            Objects.requireNonNull(target, "resource.target");
            if (target.isEmpty() || target.size() > 32) {
                throw new IllegalArgumentException("resource.target must be a bounded explicit mapping");
            }
            Map<String, Object> normalizedTarget = new TreeMap<>();
            target.forEach((name, value) -> {
                ManifestChecks.identifier(name, "target.key", 128);
                if (value instanceof String text) {
                    normalizedTarget.put(name, ManifestChecks.text(text, "target.value", 2048));
                } else if (value instanceof List<?> values && !values.isEmpty() && values.size() <= 64) {
                    List<String> strings = new ArrayList<>();
                    for (Object item : values) {
                        if (!(item instanceof String text)) {
                            throw new IllegalArgumentException("target arrays contain only strings");
                        }
                        strings.add(ManifestChecks.text(text, "target.value", 2048));
                    }
                    if (strings.stream().distinct().count() != strings.size()) {
                        throw new IllegalArgumentException("target arrays contain duplicate values");
                    }
                    normalizedTarget.put(name, strings.stream().sorted().toList());
                } else {
                    throw new IllegalArgumentException("target values must be strings or bounded string arrays");
                }
            });
            target = Map.copyOf(normalizedTarget);
            if (CanonicalJson.write(target).getBytes(java.nio.charset.StandardCharsets.UTF_8).length > 64 * 1024) {
                throw new IllegalArgumentException("resource target exceeds its byte limit");
            }
            if (access == null) {
                if (requirement == null && fieldPolicy == null) {
                    throw new IllegalArgumentException("resources need an explicit access classification");
                }
                access = ResourceAccess.PROTECTED;
            }
            allowedPrincipals = allowedPrincipals == null ? List.of(PrincipalType.USER)
                    : ManifestChecks.sortedUnique(allowedPrincipals, "allowedPrincipals", 2, Enum::name);
            if (allowedPrincipals.isEmpty()) {
                throw new IllegalArgumentException("allowedPrincipals must not be empty");
            }
            oauthScopes = oauthScopes == null ? List.of()
                    : ManifestChecks.identifiers(oauthScopes, "oauthScopes", 64, 128);
            if (access == ResourceAccess.PROTECTED && requirement == null && fieldPolicy == null
                    && !(allowedPrincipals.equals(List.of(PrincipalType.SERVICE)) && !oauthScopes.isEmpty())) {
                throw new IllegalArgumentException("protected resources need a permission or SERVICE scope rule");
            }
            if (access != ResourceAccess.PROTECTED && (requirement != null || fieldPolicy != null)) {
                throw new IllegalArgumentException("PUBLIC/INTERNAL cannot erase a protected requirement");
            }
            if (type == ResourceType.FIELD && access == ResourceAccess.PROTECTED && fieldPolicy == null) {
                throw new IllegalArgumentException("protected FIELD resources require independent field rules");
            }
            if (type != ResourceType.FIELD && fieldPolicy != null) {
                throw new IllegalArgumentException("field rules belong only to FIELD resources");
            }
            Objects.requireNonNull(i18n, "resource.i18n");
            lifecycle = lifecycle == null ? DefinitionLifecycle.ACTIVE : lifecycle;
        }
    }

    public record ResourceReference(String key, String usage) {
        public ResourceReference {
            key = ManifestChecks.identifier(key, "resourceReference.key", 200);
            usage = ManifestChecks.identifier(usage, "resourceReference.usage", 64);
            if (!Set.of("FORM_FIELD", "TABLE_FIELD", "DETAIL_FIELD", "CALLS", "PARENT", "COMPONENT").contains(usage)) {
                throw new IllegalArgumentException("unsupported resource reference usage");
            }
        }
    }

    public record Message(String pageCode, String key, String defaultLocale, Map<String, String> defaults) {
        public Message {
            pageCode = I18nSourceRules.key(pageCode);
            key = I18nSourceRules.key(key);
            defaultLocale = I18nSourceRules.locale(defaultLocale);
            Objects.requireNonNull(defaults, "message.defaults");
            if (defaults.isEmpty() || defaults.size() > 32 || !defaults.containsKey(defaultLocale)) {
                throw new IllegalArgumentException("source defaults must include the default locale");
            }
            defaults = Map.copyOf(new TreeMap<>(defaults));
            Set<String> locales = new HashSet<>();
            List<String> expectedPlaceholders = I18nSourceRules.placeholders(defaults.get(defaultLocale));
            for (Map.Entry<String, String> entry : defaults.entrySet()) {
                I18nSourceRules.locale(entry.getKey());
                if (!locales.add(entry.getKey().toLowerCase(java.util.Locale.ROOT))
                        || !expectedPlaceholders.equals(I18nSourceRules.placeholders(entry.getValue()))) {
                    throw new IllegalArgumentException("source locales must have the same placeholder contract");
                }
            }
        }
    }
}
