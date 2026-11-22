package top.egon.cola.platform.tianquan.jianshen.admin.bootstrap.domain.dto;

import top.egon.cola.platform.tianquan.jianshen.admin.registration.catalog.domain.PermissionCatalogCaller;
import top.egon.cola.platform.tianquan.jianshen.contract.permission.CanonicalJson;
import top.egon.cola.platform.tianquan.jianshen.contract.permission.CatalogScope;
import top.egon.cola.platform.tianquan.jianshen.contract.permission.PermissionManifest;

import java.net.URI;
import java.util.HashSet;
import java.util.List;
import java.util.Map;
import java.util.Objects;
import java.util.Set;
import java.util.UUID;

/** B0 operator input: a fixed catalog target and finite source owners, never a permission or role grant. */
public record PermissionCatalogBootstrapCommandDTO(int schemaVersion, String operationId, String connectionFile, CatalogScope target,
        String applicationId, String applicationName, String ddcBusinessId, String ddcApplicationId,
        List<Producer> producers) {

    public PermissionCatalogBootstrapCommandDTO {
        requireVersion(schemaVersion);
        operationId = operation(operationId);
        connectionFile = text(connectionFile, "connectionFile", 4096);
        Objects.requireNonNull(target, "target");
        applicationId = decimal(applicationId);
        applicationName = text(applicationName, "applicationName", 200);
        ddcBusinessId = identifier(ddcBusinessId, "ddcBusinessId", 64);
        ddcApplicationId = identifier(ddcApplicationId, "ddcApplicationId", 64);
        producers = Objects.requireNonNull(producers, "producers").stream().sorted(java.util.Comparator.comparing(Producer::producerId)).toList();
        if (producers.isEmpty() || producers.size() > 32) throw new IllegalArgumentException("B0 requires 1-32 producers");
        Set<String> names = new HashSet<>();
        for (Producer producer : producers) {
            if (!names.add(producer.producerId().toLowerCase(java.util.Locale.ROOT))) {
                throw new IllegalArgumentException("duplicate bootstrap producer");
            }
        }
    }

    public record Producer(String producerId, PermissionManifest.ProducerKind kind, List<String> ownedKeyPrefixes,
            List<String> ownedPermissionPrefixes, List<String> ownedMessagePrefixes, List<String> expectedModules,
            List<ServiceGrant> serviceGrants) {
        public Producer {
            producerId = identifier(producerId, "producerId", 128);
            Objects.requireNonNull(kind, "kind");
            ownedKeyPrefixes = prefixes(ownedKeyPrefixes, "ownedKeyPrefixes", true, ".:/");
            ownedPermissionPrefixes = prefixes(ownedPermissionPrefixes, "ownedPermissionPrefixes", false, ".:/_");
            ownedMessagePrefixes = prefixes(ownedMessagePrefixes, "ownedMessagePrefixes", true, ".:/");
            expectedModules = identifiers(expectedModules, "expectedModules", 256, true);
            serviceGrants = Objects.requireNonNull(serviceGrants, "serviceGrants").stream().sorted(java.util.Comparator.comparing(ServiceGrant::bindingDigest)).toList();
            if (serviceGrants.isEmpty() || serviceGrants.size() > 16) throw new IllegalArgumentException("B0 requires 1-16 service grants per producer");
            Set<String> bindings = new HashSet<>();
            for (ServiceGrant grant : serviceGrants) if (!bindings.add(grant.bindingDigest())) {
                throw new IllegalArgumentException("duplicate bootstrap service identity");
            }
        }
    }

    public record ServiceGrant(URI issuer, String clientId, URI resourceUri, List<PermissionCatalogCaller.Capability> capabilities,
            List<String> allowedSourceRefs, boolean allowPermissionExpansion) {
        public ServiceGrant {
            issuer = endpoint(issuer, "issuer");
            clientId = identifier(clientId, "clientId", 200);
            resourceUri = endpoint(resourceUri, "resourceUri");
            capabilities = Objects.requireNonNull(capabilities, "capabilities").stream().sorted(java.util.Comparator.comparing(Enum::name)).toList();
            if (capabilities.isEmpty() || new HashSet<>(capabilities).size() != capabilities.size()) {
                throw new IllegalArgumentException("service capabilities must be finite and unique");
            }
            allowedSourceRefs = identifiers(allowedSourceRefs, "allowedSourceRefs", 64, true);
            if (allowPermissionExpansion && !capabilities.contains(PermissionCatalogCaller.Capability.ACTIVATE)) {
                throw new IllegalArgumentException("permission expansion requires an explicit activation grant");
            }
        }

        public String bindingDigest() {
            return CanonicalJson.digest(Map.of("issuer", issuer.toString(), "clientId", clientId, "resourceUri", resourceUri.toString()));
        }
    }

    public static void requireVersion(int version) {
        if (version != 1) throw new IllegalArgumentException("unsupported bootstrap schemaVersion");
    }

    public static String operation(String value) {
        if (value == null || !UUID.fromString(value).toString().equals(value)) throw new IllegalArgumentException("operationId must be a canonical UUID");
        return value;
    }

    public static String decimal(String value) {
        if (value == null || !value.matches("[1-9][0-9]{0,18}") || Long.parseLong(value) <= 0) {
            throw new IllegalArgumentException("positive decimal identifier required");
        }
        return value;
    }

    public static String text(String value, String name, int maximum) {
        if (value == null || value.isBlank() || !value.equals(value.strip()) || value.length() > maximum
                || value.chars().anyMatch(Character::isISOControl)) throw new IllegalArgumentException("invalid " + name);
        return value;
    }

    public static String identifier(String value, String name, int maximum) {
        value = text(value, name, maximum);
        if (!value.matches("[A-Za-z0-9][A-Za-z0-9._:/-]*")) throw new IllegalArgumentException("invalid " + name);
        return value;
    }

    public static List<String> identifiers(List<String> values, String name, int maximum, boolean required) {
        if (values == null || values.size() > maximum || required && values.isEmpty()) throw new IllegalArgumentException("invalid " + name);
        var result = values.stream().map(value -> identifier(value, name, 200)).sorted().toList();
        if (new HashSet<>(result).size() != result.size()) throw new IllegalArgumentException("duplicate " + name);
        return result;
    }

    private static List<String> prefixes(List<String> values, String name, boolean required, String boundaryCharacters) {
        var result = identifiers(values, name, 128, required);
        if (result.stream().anyMatch(value -> boundaryCharacters.indexOf(value.charAt(value.length() - 1)) < 0)) {
            throw new IllegalArgumentException(name + " must end at an explicit namespace boundary");
        }
        return result;
    }

    private static URI endpoint(URI value, String name) {
        if (value == null || !"https".equals(value.getScheme()) || value.getHost() == null || value.getUserInfo() != null
                || value.getQuery() != null || value.getFragment() != null || !value.normalize().equals(value)) {
            throw new IllegalArgumentException("invalid HTTPS " + name);
        }
        return value;
    }
}
