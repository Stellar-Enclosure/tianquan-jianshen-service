package top.egon.cola.platform.tianquan.jianshen.contract.permission;

public record CatalogScope(
        String catalogScopeId,
        String tenantId,
        String businessCode,
        String applicationCode,
        String namespaceCode,
        String environment
) {

    public CatalogScope {
        catalogScopeId = ManifestChecks.decimal(catalogScopeId, "catalogScopeId", false);
        tenantId = ManifestChecks.decimal(tenantId, "tenantId", false);
        businessCode = ManifestChecks.identifier(businessCode, "businessCode", 128);
        applicationCode = ManifestChecks.identifier(applicationCode, "applicationCode", 128);
        namespaceCode = ManifestChecks.identifier(namespaceCode, "namespaceCode", 128);
        environment = ManifestChecks.identifier(environment, "environment", 32);
    }
}
