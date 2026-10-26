package top.egon.cola.platform.tianquan.jianshen.starter.permission;

import com.fasterxml.jackson.databind.ObjectMapper;
import org.springframework.core.io.ClassPathResource;
import top.egon.cola.platform.tianquan.jianshen.contract.authorization.SystemAuthorizationSnapshot;
import top.egon.cola.platform.tianquan.jianshen.contract.permission.*;
import top.egon.cola.platform.tianquan.jianshen.starter.client.Rbac3AuthorizationClient;
import java.io.IOException;
import java.time.Clock;
import java.util.Map;
import java.util.Objects;
import java.util.stream.Collectors;

/** Immutable compile-time policy registry, independently matched to trusted deployment evidence. */
public final class PermissionPolicyRegistry {
    public static final String MANIFEST_RESOURCE = "META-INF/permissions/manifest-v1.json";
    private static final java.util.Set<String> CONTROL_PLANE_KEYS = java.util.Set.of(
            "tianquan-jianshen.api.manifest.plan", "tianquan-jianshen.api.manifest.register", "tianquan-jianshen.api.manifest.status",
            "tianquan-jianshen.api.catalog.qualify", "tianquan-jianshen.api.catalog.activate", "tianquan-jianshen.api.catalog.descriptor",
            "tianquan-jianshen.api.catalog.versions", "tianshu.api.i18nSourceImport.importSource", "tianshu.api.i18nSourceImport.receipt",
            "tianquan-jianshen.api.runtime.userSnapshot", "tianquan-jianshen.api.runtime.servicePolicy");
    private final java.util.Set<String> bootstrapServiceResources;
    private final java.util.Set<String> anonymousResources;
    private final PermissionManifest manifest;
    private final ManifestDigests digests;
    private final String artifactDigest;
    private final Map<String, PermissionManifest.ResourceDefinition> resources;
    private final Clock clock;
    private final java.util.List<CatalogScope> expectedScopes;

    public PermissionPolicyRegistry(PermissionManifest manifest, String artifactDigest, Clock clock) {
        this(manifest, artifactDigest, clock, java.util.List.of());
    }

    public PermissionPolicyRegistry(PermissionManifest manifest, String artifactDigest, Clock clock, java.util.List<CatalogScope> expectedScopes) {
        this(manifest, artifactDigest, clock, expectedScopes, java.util.Set.of());
    }

    public PermissionPolicyRegistry(PermissionManifest manifest, String artifactDigest, Clock clock,
                                    java.util.List<CatalogScope> expectedScopes, java.util.Set<String> bootstrapServiceResources) {
        this(manifest, artifactDigest, clock, expectedScopes, bootstrapServiceResources, java.util.Set.of());
    }

    public PermissionPolicyRegistry(PermissionManifest manifest, String artifactDigest, Clock clock,
            java.util.List<CatalogScope> expectedScopes, java.util.Set<String> bootstrapServiceResources, java.util.Set<String> anonymousResources) {
        this.anonymousResources = java.util.Set.copyOf(anonymousResources);
        if (!java.util.Set.of(PermissionAnonymousBoundary.LOGIN_TEXT_KEY).containsAll(anonymousResources)
                || !anonymousResources.isEmpty() && !"tianshu".equals(manifest.application().applicationCode())) {
            throw new IllegalArgumentException("unmanaged anonymous boundary");
        }
        this.bootstrapServiceResources = java.util.Set.copyOf(bootstrapServiceResources);
        if (!CONTROL_PLANE_KEYS.containsAll(bootstrapServiceResources)) throw new IllegalArgumentException("unmanaged bootstrap resource exemption");
        this.expectedScopes = java.util.List.copyOf(expectedScopes);
        this.manifest = Objects.requireNonNull(manifest, "manifest");
        if (manifest.producer().snapshotMode() != PermissionManifest.SnapshotMode.FULL
                || manifest.producer().kind() != PermissionManifest.ProducerKind.JAVA
                || !manifest.producer().expectedModules().equals(manifest.producer().scannedModules())
                || artifactDigest == null || !artifactDigest.matches("[0-9a-f]{64}")) {
            throw new IllegalArgumentException("complete Java policy and trusted deployed artifact digest are required");
        }
        this.digests = new PermissionManifestCanonicalizer().digests(manifest);
        this.artifactDigest = artifactDigest;
        this.clock = Objects.requireNonNull(clock, "clock");
        this.resources = manifest.resources().stream().collect(Collectors.toUnmodifiableMap(PermissionManifest.ResourceDefinition::key, value -> value));
        for (String key : anonymousResources) {
            var resource = require(key, ResourceType.API);
            if (resource.access() != ResourceAccess.PUBLIC || resource.requirement() != null) {
                throw new IllegalArgumentException("native anonymous resource must be explicitly PUBLIC");
            }
        }
        for (String key : bootstrapServiceResources) {
            var resource = require(key, ResourceType.API);
            if (!resource.allowedPrincipals().contains(PermissionManifest.PrincipalType.SERVICE) || resource.oauthScopes().isEmpty()) {
                throw new IllegalArgumentException("bootstrap resource must declare SERVICE scopes");
            }
        }
    }

    public static PermissionPolicyRegistry load(ObjectMapper mapper, String artifactDigest, Clock clock, java.util.List<CatalogScope> scopes, java.util.Set<String> bootstrapKeys, java.util.Set<String> anonymousKeys) {
        if (scopes == null || scopes.isEmpty()) throw new IllegalStateException("TRUSTED_RUNTIME_CATALOG_SCOPES_REQUIRED");
        try (var input = new ClassPathResource(MANIFEST_RESOURCE).getInputStream()) {
            byte[] bytes = input.readNBytes(PermissionManifest.MAX_BYTES + 1);
            if (bytes.length > PermissionManifest.MAX_BYTES) throw new IllegalArgumentException("compiled permission manifest is too large");
            ObjectMapper strict = mapper.copy().enable(com.fasterxml.jackson.core.JsonParser.Feature.STRICT_DUPLICATE_DETECTION);
            Map<String, Object> value = strict.readValue(bytes, Map.class);
            return new PermissionPolicyRegistry(new PermissionManifestReader().read(value), artifactDigest, clock, scopes, bootstrapKeys, anonymousKeys);
        } catch (IOException failure) {
            throw new IllegalStateException("COMPILED_PERMISSION_MANIFEST_REQUIRED", failure);
        }
    }

    public boolean anonymousResource(String key) { return anonymousResources.contains(key); }

    public boolean bootstrapServiceResource(String key) { return bootstrapServiceResources.contains(key); }

    public void requireBootstrapServiceIdentity(top.egon.cola.platform.tianquan.shoubing.contract.ServiceIdentityPrincipal caller) {
        if (caller == null || caller.scopeContext() != top.egon.cola.platform.tianquan.shoubing.contract.ServiceTokenContext.TENANT
                || !caller.expiresAt().isAfter(clock.instant()) || expectedScopes.stream().noneMatch(scope -> scope.tenantId().equals(caller.tenantId())
                && scope.applicationCode().equals(manifest.application().applicationCode()) && scope.businessCode().equals(manifest.application().businessCode()))) {
            throw new Rbac3AuthorizationClient.AuthorizationDeniedException("BOOTSTRAP_SERVICE_BINDING_MISMATCH");
        }
    }

    /** Only these owned control-plane response types may be projected before the first active catalog exists. */
    public boolean bootstrapResponseField(String apiKey, PermissionManifest.ResourceDefinition field) {
        String dto = switch (apiKey) {
            case "tianquan-jianshen.api.manifest.plan" -> "top.egon.cola.platform.tianquan.jianshen.admin.registration.catalog.service.PermissionManifestPlanService.Result";
            case "tianquan-jianshen.api.manifest.register", "tianquan-jianshen.api.manifest.status" -> "top.egon.cola.platform.tianquan.jianshen.admin.registration.catalog.service.PermissionManifestRegistrationService.Result";
            case "tianquan-jianshen.api.catalog.qualify" -> "top.egon.cola.platform.tianquan.jianshen.admin.registration.catalog.domain.vo.DeploymentQualificationReceiptVO";
            case "tianquan-jianshen.api.catalog.versions" -> "top.egon.cola.platform.tianquan.jianshen.admin.registration.catalog.repository.PermissionCatalogActivationRepository.History";
            default -> null;
        };
        return dto != null && bootstrapServiceResource(apiKey) && dto.equals(field.target().get("dto"))
                && field.type() == ResourceType.FIELD && field.access() == ResourceAccess.PUBLIC && field.lifecycle() == DefinitionLifecycle.ACTIVE
                && field.allowedPrincipals().contains(PermissionManifest.PrincipalType.SERVICE)
                && java.util.Set.copyOf(field.oauthScopes()).equals(java.util.Set.copyOf(require(apiKey, ResourceType.API).oauthScopes()));
    }


    public PermissionManifest.ResourceDefinition require(String key, ResourceType type) {
        var resource = resources.get(key);
        if (resource == null || resource.type() != type) throw new IllegalStateException("COMPILED_PERMISSION_RESOURCE_MISSING");
        return resource;
    }

    public Map<String, PermissionManifest.ResourceDefinition> fields(Class<?> dto) {
        var owners = new java.util.HashSet<String>();
        for (Class<?> current = dto; current != null && current != Object.class; current = current.getSuperclass()) {
            owners.add(current.getCanonicalName() == null ? current.getName() : current.getCanonicalName());
        }
        return resources.values().stream().filter(resource -> resource.type() == ResourceType.FIELD
                        && owners.contains(resource.target().get("dto")))
                .collect(Collectors.toUnmodifiableMap(resource -> resource.target().get("property").toString(), resource -> resource));
    }

    public void requireActive(SystemAuthorizationSnapshot snapshot, String resourceKey) {
        var binding = snapshot == null ? null : snapshot.policyBinding();
        var view = snapshot == null ? null : snapshot.permissionSnapshot();
        requireBinding(view == null ? null : view.catalogScope(), binding, snapshot == null ? null : snapshot.expiresAt(),
                snapshot == null ? java.util.Set.of() : snapshot.resourceCodes(), resourceKey);
    }

    public void requireActive(top.egon.cola.platform.tianquan.jianshen.contract.authorization.ServicePolicySnapshot snapshot, String key) {
        if (snapshot == null) throw new Rbac3AuthorizationClient.AuthorizationDeniedException("SERVICE_POLICY_UNAVAILABLE");
        requireBinding(snapshot.catalogScope(), snapshot.policyBinding(), snapshot.expiresAt(), snapshot.resourceKeys(), key);
    }

    private void requireBinding(CatalogScope scope,
            top.egon.cola.platform.tianquan.jianshen.contract.authorization.RuntimePolicyBinding binding,
            java.time.Instant expiry, java.util.Set<String> keys, String resourceKey) {
        if (binding == null || scope == null || expiry == null || !expiry.isAfter(clock.instant())
                || !expectedScopes.contains(scope) || !manifest.producer().id().equals(binding.producerId())
                || !artifactDigest.equals(binding.artifactDigest()) || !digests.policyDigest().equals(binding.policyDigest())
                || !digests.manifestDigest().equals(binding.manifestDigest())
                || !manifest.application().applicationCode().equals(scope.applicationCode())
                || !manifest.application().businessCode().equals(scope.businessCode()) || !keys.contains(resourceKey)) {
            throw new Rbac3AuthorizationClient.AuthorizationDeniedException("AUTH_DEPLOYMENT_BINDING_MISMATCH");
        }
    }
}
