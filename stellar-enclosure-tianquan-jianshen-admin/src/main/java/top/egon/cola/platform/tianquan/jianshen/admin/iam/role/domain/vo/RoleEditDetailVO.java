package top.egon.cola.platform.tianquan.jianshen.admin.iam.role.domain.vo;

import com.fasterxml.jackson.annotation.JsonInclude;
import io.swagger.v3.oas.annotations.media.Schema;
import top.egon.cola.platform.tianquan.jianshen.contract.permission.PermissionManifest.JsonFieldType;
import top.egon.cola.platform.tianquan.jianshen.contract.permission.ResourceType;
import top.egon.cola.platform.tianquan.jianshen.contract.permission.annotation.FieldPermissions;
import top.egon.cola.platform.tianquan.jianshen.contract.permission.annotation.PermissionGroup;
import top.egon.cola.platform.tianquan.jianshen.contract.permission.annotation.PermissionResource;

/** Original editable values and the optimistic-lock version from the same role row. */
public record RoleEditDetailVO(
    @PermissionResource(key = "tianquan-jianshen.field.iam.role.domain.vo.RoleEditDetailVO.roleId",
            type = ResourceType.FIELD, labelPage = "tianquan-jianshen.permissions", labelKey = "field.roleId")
    @FieldPermissions(valueType = JsonFieldType.STRING, plainRead = @PermissionGroup(codes = "system:role:update"))
    String roleId,

    @PermissionResource(key = "tianquan-jianshen.field.iam.role.domain.vo.RoleEditDetailVO.applicationId",
            type = ResourceType.FIELD, labelPage = "tianquan-jianshen.permissions", labelKey = "field.applicationId")
    @FieldPermissions(valueType = JsonFieldType.STRING, plainRead = @PermissionGroup(codes = "system:role:update"))
    String applicationId,

    @PermissionResource(key = "tianquan-jianshen.field.iam.role.domain.vo.RoleEditDetailVO.roleName",
            type = ResourceType.FIELD, labelPage = "tianquan-jianshen.permissions", labelKey = "field.roleName")
    @FieldPermissions(valueType = JsonFieldType.STRING, plainRead = @PermissionGroup(codes = "system:role:update"))
    String roleName,

    @PermissionResource(key = "tianquan-jianshen.field.iam.role.domain.vo.RoleEditDetailVO.status",
            type = ResourceType.FIELD, labelPage = "tianquan-jianshen.permissions", labelKey = "field.status")
    @FieldPermissions(valueType = JsonFieldType.STRING, plainRead = @PermissionGroup(codes = "system:role:update"))
    @Schema(allowableValues = {"ACTIVE", "DISABLED", "ARCHIVED"})
    String status,

    @PermissionResource(key = "tianquan-jianshen.field.iam.role.domain.vo.RoleEditDetailVO.landingRouteId",
            type = ResourceType.FIELD, labelPage = "tianquan-jianshen.permissions", labelKey = "field.landingRouteId")
    @FieldPermissions(valueType = JsonFieldType.STRING, plainRead = @PermissionGroup(codes = "system:role:update"))
    @JsonInclude(JsonInclude.Include.ALWAYS)
    @Schema(types = {"string", "null"}, requiredMode = Schema.RequiredMode.REQUIRED)
    String landingRouteId,

    @PermissionResource(key = "tianquan-jianshen.field.iam.role.domain.vo.RoleEditDetailVO.landingPriority",
            type = ResourceType.FIELD, labelPage = "tianquan-jianshen.permissions", labelKey = "field.landingPriority")
    @FieldPermissions(valueType = JsonFieldType.NUMBER, plainRead = @PermissionGroup(codes = "system:role:update"))
    @Schema(minimum = "0")
    int landingPriority,

    @PermissionResource(key = "tianquan-jianshen.field.iam.role.domain.vo.RoleEditDetailVO.maximumAssignmentDays",
            type = ResourceType.FIELD, labelPage = "tianquan-jianshen.permissions", labelKey = "field.maximumAssignmentDays")
    @FieldPermissions(valueType = JsonFieldType.NUMBER, plainRead = @PermissionGroup(codes = "system:role:update"))
    @JsonInclude(JsonInclude.Include.ALWAYS)
    @Schema(types = {"integer", "null"}, minimum = "1", requiredMode = Schema.RequiredMode.REQUIRED)
    Integer maximumAssignmentDays,

    @PermissionResource(key = "tianquan-jianshen.field.iam.role.domain.vo.RoleEditDetailVO.version",
            type = ResourceType.FIELD, labelPage = "tianquan-jianshen.permissions", labelKey = "field.version")
    @FieldPermissions(valueType = JsonFieldType.NUMBER, plainRead = @PermissionGroup(codes = "system:role:update"))
    @Schema(minimum = "0", format = "int64")
    long version
) { }
