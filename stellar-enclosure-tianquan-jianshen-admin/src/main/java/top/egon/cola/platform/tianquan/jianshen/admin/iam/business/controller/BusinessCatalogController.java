package top.egon.cola.platform.tianquan.jianshen.admin.iam.business.controller;

import top.egon.cola.platform.tianquan.jianshen.contract.permission.annotation.PermissionResource;

import top.egon.cola.platform.tianquan.jianshen.contract.permission.ResourceAccess;

import top.egon.cola.platform.tianquan.jianshen.contract.permission.ResourceType;

import top.egon.cola.platform.tianquan.jianshen.contract.permission.PermissionManifest;

import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PathVariable;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.RestController;
import top.egon.cola.component.common.core.pojo.ResultRecord;
import io.swagger.v3.oas.annotations.Operation;
import io.swagger.v3.oas.annotations.tags.Tag;
import top.egon.cola.component.yuheng.openapi.annotation.EgonApiCatalog;
import top.egon.cola.component.yuheng.openapi.annotation.EgonGatewayPolicy;
import top.egon.cola.platform.tianquan.jianshen.admin.iam.business.domain.vo.ApplicationCatalogEntry;
import top.egon.cola.platform.tianquan.jianshen.admin.iam.business.domain.vo.BusinessCatalogEntry;
import top.egon.cola.platform.tianquan.jianshen.admin.iam.business.service.BusinessCatalogService;
import top.egon.cola.platform.tianquan.jianshen.contract.permission.annotation.RequiresPermissions;

import java.util.List;

/** Read-only Tianshu Business/Application catalog endpoints. */
@RestController
@RequestMapping("/api/tianquan-jianshen/v1/iam/catalog")
@Tag(name = "business-catalog", description = "业务域与应用目录接口组")
@EgonApiCatalog(
        businessDomainCode = "xingyuan",
        businessDomainName = "平台治理域",
        entityDomainCode = "tianquan-jianshen",
        entityDomainName = "Tianquan-Jianshen权限实体域",
        interfaceGroupCode = "iam"
)
public class BusinessCatalogController {

    private final BusinessCatalogService service;

    public BusinessCatalogController(BusinessCatalogService service) {
        this.service = service;
    }

    @PermissionResource(key = "tianquan-jianshen.api.BusinessCatalog.businesses", type = ResourceType.API,
            labelPage = "tianquan-jianshen.permissions", labelKey = "api.BusinessCatalog.businesses")
    @GetMapping("/businesses")
    @RequiresPermissions(codes = "system:business:read")
    @Operation(
            operationId = "tianquan-jianshen-business-catalog-list-v1",
            summary = "查询 Tianshu 业务域目录",
            tags = {"tianquan-jianshen", "business"}
    )
    @EgonGatewayPolicy(
            exposure = EgonGatewayPolicy.Exposure.EXTERNAL
    )
    public ResultRecord<List<BusinessCatalogEntry>> businesses(
            @RequestParam(name = "keyword", required = false) String keyword) {
        return ResultRecord.success(service.businesses(keyword));
    }

    @PermissionResource(key = "tianquan-jianshen.api.BusinessCatalog.applications", type = ResourceType.API,
            labelPage = "tianquan-jianshen.permissions", labelKey = "api.BusinessCatalog.applications")
    @GetMapping("/businesses/{ddcBusinessId}/applications")
    @RequiresPermissions(codes = "system:application:read")
    @Operation(
            operationId = "tianquan-jianshen-business-catalog-applications-v1",
            summary = "查询 Tianshu 业务域下的应用目录",
            tags = {"tianquan-jianshen", "business", "application"}
    )
    @EgonGatewayPolicy(
            exposure = EgonGatewayPolicy.Exposure.EXTERNAL
    )
    public ResultRecord<List<ApplicationCatalogEntry>> applications(
            @PathVariable String ddcBusinessId,
            @RequestParam(name = "keyword", required = false) String keyword) {
        return ResultRecord.success(service.applications(ddcBusinessId, keyword));
    }
}
