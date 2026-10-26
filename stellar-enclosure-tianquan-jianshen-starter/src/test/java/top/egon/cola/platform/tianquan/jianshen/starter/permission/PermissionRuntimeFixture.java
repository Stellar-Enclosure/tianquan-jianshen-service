package top.egon.cola.platform.tianquan.jianshen.starter.permission;

import java.time.*;
import java.util.*;
import org.springframework.security.core.context.SecurityContextHolder;
import top.egon.cola.platform.tianquan.jianshen.contract.authorization.*;
import top.egon.cola.platform.tianquan.jianshen.contract.permission.*;
import top.egon.cola.platform.tianquan.jianshen.starter.security.*;
import top.egon.cola.platform.tianquan.shoubing.contract.*;

public final class PermissionRuntimeFixture {
    public static final Instant NOW = Instant.parse("2026-10-25T00:00:00Z");
    public static final Clock CLOCK = Clock.fixed(NOW, ZoneOffset.UTC);
    public static final CatalogScope SCOPE = new CatalogScope("10", "20", "commerce", "shop", "default", "test");
    public static final String ARTIFACT = "a".repeat(64);
    public static final IdentityPrincipal USER = new IdentityPrincipal("30", "20", "40", Set.of("https://api.example/shop"),
            NOW.minusSeconds(10), NOW.plusSeconds(300), AuthenticationContext.of("PASSWORD", NOW.minusSeconds(20)));

    public static PermissionManifest manifest(List<PermissionManifest.ResourceDefinition> resources) {
        return new PermissionManifest("1.0", new PermissionManifest.Application("commerce", "shop"),
                new PermissionManifest.Producer("shop-java", PermissionManifest.ProducerKind.JAVA, PermissionManifest.SnapshotMode.FULL,
                        List.of("shop."), List.of("app"), List.of("app"), false),
                new PermissionManifest.Artifact("https://example.com/repo", "a".repeat(40), "build-1", "1"),
                List.of(), List.of("order:read", "order:write", "order:approve", "field:plain", "field:masked", "field:write"),
                resources, List.of(), List.of());
    }
    public static PermissionManifest.ResourceDefinition field(Class<?> dto, String name, ResourceAccess access,
                                                               PermissionManifest.FieldPolicy policy) {
        return new PermissionManifest.ResourceDefinition("shop.field." + dto.getSimpleName() + "." + name, ResourceType.FIELD,
                Map.of("dto", dto.getCanonicalName(), "property", name), access, null, policy,
                List.of(PermissionManifest.PrincipalType.USER), List.of(), new PermissionManifest.I18nReference("shop", name), DefinitionLifecycle.ACTIVE);
    }
    public static PermissionRequirement all(String code) { return new PermissionRequirement(PermissionMode.ALL, List.of(code)); }
    public static PermissionPolicyRegistry registry(PermissionManifest manifest) {
        return new PermissionPolicyRegistry(manifest, ARTIFACT, CLOCK, List.of(SCOPE));
    }
    public static SystemAuthorizationSnapshot snapshot(PermissionManifest manifest, Set<String> permissions) {
        var digests = new PermissionManifestCanonicalizer().digests(manifest);
        var view = new EffectivePermissionSnapshot("https://idp.example/tenants/20", USER.subject(), SCOPE, "1", "2", "3",
                new EffectivePermissionSnapshot.ActiveRoleContext("shop", List.of("50"), List.of("50")),
                permissions.stream().sorted().toList(), NOW.plusSeconds(30));
        return new SystemAuthorizationSnapshot("20", USER.subject(), "60", "shop", 2, 3, List.of("50"), null, null,
                permissions, manifest.resources().stream().map(PermissionManifest.ResourceDefinition::key).collect(java.util.stream.Collectors.toSet()),
                Map.of(), Map.of(), "checksum", NOW, view.snapshotExpiresAt(), view,
                new RuntimePolicyBinding("shop-java", "1", ARTIFACT, digests.policyDigest(), digests.manifestDigest()));
    }
    public static void authenticate(PermissionManifest manifest, Set<String> permissions) {
        SecurityContextHolder.getContext().setAuthentication(new Rbac3AuthenticationToken(new Rbac3UserDetails(USER, snapshot(manifest, permissions))));
    }
}
