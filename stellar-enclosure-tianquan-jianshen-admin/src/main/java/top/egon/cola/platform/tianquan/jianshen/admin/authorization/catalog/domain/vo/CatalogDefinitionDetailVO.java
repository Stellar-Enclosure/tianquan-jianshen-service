package top.egon.cola.platform.tianquan.jianshen.admin.authorization.catalog.domain.vo;

import top.egon.cola.platform.tianquan.jianshen.contract.permission.annotation.PermissionResource;
import top.egon.cola.platform.tianquan.jianshen.contract.permission.annotation.PermissionGroup;
import top.egon.cola.platform.tianquan.jianshen.contract.permission.annotation.FieldPermissions;
import top.egon.cola.platform.tianquan.jianshen.contract.permission.ResourceType;
import top.egon.cola.platform.tianquan.jianshen.contract.permission.PermissionManifest;

/** Immutable catalog transport value; persistence and orchestration stay outside this package. */
public record CatalogDefinitionDetailVO(@PermissionResource(key = "tianquan-jianshen.field.authorization.catalog.domain.vo.CatalogDefinitionDetailVO.identity", type = ResourceType.FIELD,
                labelPage = "tianquan-jianshen.permissions", labelKey = "field.identity")
        @FieldPermissions(valueType = PermissionManifest.JsonFieldType.OBJECT,
                plainRead = @PermissionGroup(codes = {"system:permission-catalog:read"}))
        CatalogDefinitionVO identity, @PermissionResource(key = "tianquan-jianshen.field.authorization.catalog.domain.vo.CatalogDefinitionDetailVO.activeProducerVersion", type = ResourceType.FIELD,
                labelPage = "tianquan-jianshen.permissions", labelKey = "field.activeProducerVersion")
        @FieldPermissions(valueType = PermissionManifest.JsonFieldType.STRING,
                plainRead = @PermissionGroup(codes = {"system:permission-catalog:read"}))
        String activeProducerVersion, @PermissionResource(key = "tianquan-jianshen.field.authorization.catalog.domain.vo.CatalogDefinitionDetailVO.activeDefinition", type = ResourceType.FIELD,
                labelPage = "tianquan-jianshen.permissions", labelKey = "field.activeDefinition")
        @FieldPermissions(valueType = PermissionManifest.JsonFieldType.OBJECT,
                plainRead = @PermissionGroup(codes = {"system:permission-catalog:read"}))
        java.util.Map<String, Object> activeDefinition) { }
