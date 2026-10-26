package top.egon.cola.platform.tianquan.jianshen.admin.authorization.runtime.catalog;

import jakarta.servlet.http.HttpServletRequest;
import org.springframework.beans.factory.ObjectProvider;
import org.springframework.beans.factory.annotation.Qualifier;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;
import org.springframework.web.servlet.mvc.method.annotation.RequestMappingHandlerAdapter;
import org.springframework.web.servlet.mvc.method.annotation.RequestMappingHandlerMapping;
import top.egon.cola.component.common.core.pojo.ResultRecord;
import top.egon.cola.platform.tianquan.jianshen.contract.permission.*;
import top.egon.cola.platform.tianquan.jianshen.contract.permission.annotation.*;
import top.egon.cola.platform.tianquan.jianshen.starter.permission.PermissionFieldCatalog;
import top.egon.cola.platform.tianquan.jianshen.admin.authorization.policy.domain.dto.DataRuleRequestDTO;
import top.egon.cola.platform.tianquan.jianshen.admin.authorization.grant.rolepermission.domain.dto.ReplaceRolePermissionsRequestDTO;
import top.egon.cola.platform.tianquan.jianshen.admin.authorization.catalog.domain.dto.CatalogGovernanceCommandDTO;
import java.util.Set;

/** A finite projection of FIELD policy and the registered HTTP input DTO graph. */
@RestController
@PermissionMessage(pageCode="permission.runtime",key="fields",defaultLocale="en",defaults=@LocalizedText(locale="en",text="Read field policies and input bindings"))
public class FieldCatalogController {
    private static final String KEY="tianquan-jianshen.api.authorization.fields";
    private static final String ADMIN="top.egon.cola.platform.tianquan.jianshen.admin.";
    private final PermissionFieldCatalog fields;
    private final ObjectProvider<RequestMappingHandlerAdapter> adapters;
    private final ObjectProvider<RequestMappingHandlerMapping> routes;

    public FieldCatalogController(PermissionFieldCatalog fields,
            @Qualifier("requestMappingHandlerAdapter") ObjectProvider<RequestMappingHandlerAdapter> adapters,
            @Qualifier("requestMappingHandlerMapping") ObjectProvider<RequestMappingHandlerMapping> routes) {
        this.fields=fields;this.adapters=adapters;this.routes=routes;
    }

    @GetMapping("/api/v1/authorization/field-catalog")
    @PermissionResource(key=KEY,type=ResourceType.API,labelPage="permission.runtime",labelKey="fields",
            access=ResourceAccess.PUBLIC,allowedPrincipals=PermissionManifest.PrincipalType.USER)
    public ResponseEntity<ResultRecord<FieldCatalogSnapshot>> current(HttpServletRequest request) {
        return ResponseEntity.ok().header("Cache-Control","no-store")
                .body(ResultRecord.success(fields.currentForHttp(request,KEY,adapters.getObject().getMessageConverters(),routes.getObject().getHandlerMethods().values(),
                        Set.of(ADMIN),Set.of(DataRuleRequestDTO.class,ReplaceRolePermissionsRequestDTO.class,CatalogGovernanceCommandDTO.class))));
    }
}
