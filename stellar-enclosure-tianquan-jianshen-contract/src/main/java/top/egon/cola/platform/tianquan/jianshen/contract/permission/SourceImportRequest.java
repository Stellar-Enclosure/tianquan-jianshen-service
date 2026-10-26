package top.egon.cola.platform.tianquan.jianshen.contract.permission;

import java.util.Map;
import java.util.Objects;
import java.util.TreeMap;
import java.util.UUID;

public record SourceImportRequest(
        String operationId,
        CatalogScope scope,
        String producerId,
        String producerVersion,
        String sourceVersion,
        PermissionManifest manifest,
        ManifestDigests digests,
        Map<String, String> resourceIds,
        Map<String, String> permissionIds
) {

    public SourceImportRequest {
        if (operationId == null || !UUID.fromString(operationId).toString().equals(operationId)) {
            throw new IllegalArgumentException("operationId must be a canonical UUID");
        }
        Objects.requireNonNull(scope, "scope");
        producerId = ManifestChecks.identifier(producerId, "producerId", 128);
        producerVersion = ManifestChecks.decimal(producerVersion, "producerVersion", false);
        sourceVersion = ManifestChecks.hash(sourceVersion, "sourceVersion");
        Objects.requireNonNull(manifest, "manifest");
        Objects.requireNonNull(digests, "digests");
        if (!producerId.equals(manifest.producer().id())
                || !scope.businessCode().equals(manifest.application().businessCode())
                || !scope.applicationCode().equals(manifest.application().applicationCode())
                || !sourceVersion.equals(digests.manifestDigest())
                || !digests.equals(new PermissionManifestCanonicalizer().digests(manifest))) {
            throw new IllegalArgumentException("source import scope, producer or digests do not match");
        }
        resourceIds = immutableIds(resourceIds, "resourceIds", 200);
        permissionIds = immutableIds(permissionIds, "permissionIds", 128);
        if (!resourceIds.keySet().equals(manifest.resources().stream()
                .map(PermissionManifest.ResourceDefinition::key).collect(java.util.stream.Collectors.toSet()))
                || !permissionIds.keySet().equals(manifest.permissionDefinitions().stream()
                .map(PermissionManifest.PermissionDefinition::code).collect(java.util.stream.Collectors.toSet()))) {
            throw new IllegalArgumentException("centre IDs must exactly cover owned definitions");
        }
    }

    static Map<String, String> immutableIds(Map<String, String> ids, String name, int keyLength) {
        Objects.requireNonNull(ids, name);
        if (ids.size() > 10_000) throw new IllegalArgumentException(name + " exceeds its limit");
        Map<String, String> result = Map.copyOf(new TreeMap<>(ids));
        result.forEach((key, id) -> {
            ManifestChecks.identifier(key, name, keyLength);
            ManifestChecks.decimal(id, name, false);
        });
        if (result.values().stream().distinct().count() != result.size()) {
            throw new IllegalArgumentException(name + " contains reused centre IDs");
        }
        if (CanonicalJson.write(result).getBytes(java.nio.charset.StandardCharsets.UTF_8).length > 2 * 1024 * 1024) {
            throw new IllegalArgumentException(name + " exceeds its byte limit");
        }
        return result;
    }

    public String projectionDigest() {
        return CanonicalJson.digest(Map.of("scope", scopeMap(), "producerId", producerId,
                "sourceVersion", sourceVersion, "resourceIds", resourceIds, "permissionIds", permissionIds));
    }

    public String requestDigest() {
        return CanonicalJson.digest(Map.of("operationId", operationId, "scope", scopeMap(),
                "producerId", producerId, "producerVersion", producerVersion, "sourceVersion", sourceVersion,
                "policyDigest", digests.policyDigest(), "metadataDigest", digests.metadataDigest(),
                "manifestDigest", digests.manifestDigest(), "projectionDigest", projectionDigest()));
    }

    public Map<String, Object> scopeMap() {
        return Map.of("catalogScopeId", scope.catalogScopeId(), "tenantId", scope.tenantId(),
                "businessCode", scope.businessCode(), "applicationCode", scope.applicationCode(),
                "namespaceCode", scope.namespaceCode(), "environment", scope.environment());
    }
}
