package top.egon.cola.platform.tianquan.jianshen.admin.authorization.runtime.catalog;

import top.egon.cola.platform.tianquan.jianshen.admin.registration.catalog.domain.PermissionCatalogCaller;
import top.egon.cola.platform.tianquan.jianshen.admin.registration.catalog.repository.PermissionCatalogScopeRepository;
import top.egon.cola.platform.tianquan.jianshen.contract.permission.CatalogScope;
import top.egon.cola.platform.tianquan.jianshen.contract.permission.DefinitionLifecycle;
import top.egon.cola.platform.tianquan.jianshen.contract.permission.PermissionManifest;
import top.egon.cola.platform.tianquan.jianshen.contract.permission.PermissionMode;
import top.egon.cola.platform.tianquan.jianshen.contract.permission.PermissionRequirement;
import top.egon.cola.platform.tianquan.jianshen.contract.permission.ResourceAccess;
import top.egon.cola.platform.tianquan.jianshen.contract.permission.ResourceType;
import top.egon.cola.platform.tianquan.shoubing.contract.ServiceIdentityPrincipal;
import top.egon.cola.platform.tianquan.shoubing.contract.ServiceTokenContext;

import java.net.URI;
import java.time.Instant;
import java.util.List;
import java.util.Map;
import java.util.Set;

final class RuntimeCatalogPostgresqlFixture {

    static final Instant NOW = Instant.parse("2026-10-25T00:00:00Z");
    static final CatalogScope SCOPE = new CatalogScope("1", "10", "biz", "app", "default", "test");
    static final String OPERATION = "00000000-0000-0000-0000-000000000001";

    static PermissionManifest manifest() {
        var i18n = new PermissionManifest.I18nReference("app", "read");
        return new PermissionManifest("1.0", new PermissionManifest.Application("biz", "app"),
                new PermissionManifest.Producer("api", PermissionManifest.ProducerKind.JAVA, PermissionManifest.SnapshotMode.FULL,
                        List.of("app."), List.of("api"), List.of("api"), false),
                new PermissionManifest.Artifact("demo", "a".repeat(40), "build", "1"),
                List.of(new PermissionManifest.PermissionDefinition("app.read", "Read app records", i18n, DefinitionLifecycle.ACTIVE)), List.of(),
                List.of(new PermissionManifest.ResourceDefinition("app.read", ResourceType.API, Map.of("path", "/records"), ResourceAccess.PROTECTED,
                        new PermissionRequirement(PermissionMode.ALL, List.of("app.read")), null,
                        List.of(PermissionManifest.PrincipalType.USER), List.of(), i18n, DefinitionLifecycle.ACTIVE)), List.of(),
                List.of(new PermissionManifest.Message("app", "read", "en", Map.of("en", "Read records"))));
    }

    static PermissionCatalogScopeRepository.Owner owner(long revision) {
        return new PermissionCatalogScopeRepository.Owner(SCOPE, 20, "api", PermissionManifest.ProducerKind.JAVA,
                List.of("app."), List.of("app."), List.of("app/"), List.of("api"), revision, 5, 0, 0);
    }

    static PermissionCatalogScopeRepository.Grant grant() {
        return new PermissionCatalogScopeRepository.Grant(30, 2, Set.of("REGISTER", "CLEAR_PRODUCER"), Set.of("refs/heads/main"), false);
    }

    static PermissionCatalogCaller caller() {
        return new PermissionCatalogCaller(URI.create("https://issuer.example/tenants/10"), new ServiceIdentityPrincipal(
                "pipeline", "10", "pipeline", "token", URI.create("https://rbac.example"), 1,
                Set.of(PermissionCatalogCaller.Capability.REGISTER.scope(), PermissionCatalogCaller.Capability.CLEAR_PRODUCER.scope()),
                "infra", "publisher", "test", "credential", NOW.minusSeconds(1), NOW.plusSeconds(3600), "pipeline-app", ServiceTokenContext.TENANT));
    }
}
