package top.egon.cola.platform.tianquan.jianshen.admin.authorization.catalog.domain.vo;

import top.egon.cola.platform.tianquan.jianshen.contract.permission.annotation.PermissionResource;
import top.egon.cola.platform.tianquan.jianshen.contract.permission.annotation.PermissionGroup;
import top.egon.cola.platform.tianquan.jianshen.contract.permission.annotation.FieldPermissions;
import top.egon.cola.platform.tianquan.jianshen.contract.permission.ResourceType;
import top.egon.cola.platform.tianquan.jianshen.contract.permission.PermissionMode;
import top.egon.cola.platform.tianquan.jianshen.contract.permission.PermissionManifest;

/** Immutable catalog transport value; persistence and orchestration stay outside this package. */
public record CatalogDefinitionVO(@PermissionResource(key = "tianquan-jianshen.field.authorization.catalog.domain.vo.CatalogDefinitionVO.id", type = ResourceType.FIELD,
                labelPage = "tianquan-jianshen.permissions", labelKey = "field.id")
        @FieldPermissions(valueType = PermissionManifest.JsonFieldType.STRING,
                plainRead = @PermissionGroup(mode = PermissionMode.ANY, codes = {"system:permission-catalog:manage", "system:permission-catalog:read"}))
        String id, @PermissionResource(key = "tianquan-jianshen.field.authorization.catalog.domain.vo.CatalogDefinitionVO.key", type = ResourceType.FIELD,
                labelPage = "tianquan-jianshen.permissions", labelKey = "field.key")
        @FieldPermissions(valueType = PermissionManifest.JsonFieldType.STRING,
                plainRead = @PermissionGroup(mode = PermissionMode.ANY, codes = {"system:permission-catalog:manage", "system:permission-catalog:read"}))
        String key, @PermissionResource(key = "tianquan-jianshen.field.authorization.catalog.domain.vo.CatalogDefinitionVO.producerId", type = ResourceType.FIELD,
                labelPage = "tianquan-jianshen.permissions", labelKey = "field.producerId")
        @FieldPermissions(valueType = PermissionManifest.JsonFieldType.STRING,
                plainRead = @PermissionGroup(mode = PermissionMode.ANY, codes = {"system:permission-catalog:manage", "system:permission-catalog:read"}))
        String producerId, @PermissionResource(key = "tianquan-jianshen.field.authorization.catalog.domain.vo.CatalogDefinitionVO.state", type = ResourceType.FIELD,
                labelPage = "tianquan-jianshen.permissions", labelKey = "field.state")
        @FieldPermissions(valueType = PermissionManifest.JsonFieldType.STRING,
                plainRead = @PermissionGroup(mode = PermissionMode.ANY, codes = {"system:permission-catalog:manage", "system:permission-catalog:read"}))
        String state, @PermissionResource(key = "tianquan-jianshen.field.authorization.catalog.domain.vo.CatalogDefinitionVO.version", type = ResourceType.FIELD,
                labelPage = "tianquan-jianshen.permissions", labelKey = "field.version")
        @FieldPermissions(valueType = PermissionManifest.JsonFieldType.STRING,
                plainRead = @PermissionGroup(mode = PermissionMode.ANY, codes = {"system:permission-catalog:manage", "system:permission-catalog:read"}))
        String version, @PermissionResource(key = "tianquan-jianshen.field.authorization.catalog.domain.vo.CatalogDefinitionVO.type", type = ResourceType.FIELD,
                labelPage = "tianquan-jianshen.permissions", labelKey = "field.type")
        @FieldPermissions(valueType = PermissionManifest.JsonFieldType.STRING,
                plainRead = @PermissionGroup(mode = PermissionMode.ANY, codes = {"system:permission-catalog:manage", "system:permission-catalog:read"}))
        String type, @PermissionResource(key = "tianquan-jianshen.field.authorization.catalog.domain.vo.CatalogDefinitionVO.meaning", type = ResourceType.FIELD,
                labelPage = "tianquan-jianshen.permissions", labelKey = "field.meaning")
        @FieldPermissions(valueType = PermissionManifest.JsonFieldType.STRING,
                plainRead = @PermissionGroup(mode = PermissionMode.ANY, codes = {"system:permission-catalog:manage", "system:permission-catalog:read"}))
        String meaning,
        @PermissionResource(key = "tianquan-jianshen.field.authorization.catalog.domain.vo.CatalogDefinitionVO.activeProducerVersion", type = ResourceType.FIELD,
                labelPage = "tianquan-jianshen.permissions", labelKey = "field.activeProducerVersion")
        @FieldPermissions(valueType = PermissionManifest.JsonFieldType.STRING,
                plainRead = @PermissionGroup(mode = PermissionMode.ANY, codes = {"system:permission-catalog:manage", "system:permission-catalog:read"}))
        @com.fasterxml.jackson.annotation.JsonInclude(com.fasterxml.jackson.annotation.JsonInclude.Include.ALWAYS) String activeProducerVersion) { }
