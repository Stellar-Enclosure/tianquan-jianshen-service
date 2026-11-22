package top.egon.cola.platform.tianquan.jianshen.admin.iam.role.controller;

import top.egon.cola.platform.tianquan.jianshen.contract.permission.annotation.PermissionResource;

import top.egon.cola.platform.tianquan.jianshen.contract.permission.ResourceAccess;

import top.egon.cola.platform.tianquan.jianshen.contract.permission.ResourceType;

import top.egon.cola.platform.tianquan.jianshen.contract.permission.PermissionManifest;

import jakarta.servlet.http.HttpServletResponse;
import jakarta.validation.Valid;
import jakarta.validation.constraints.Pattern;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Qualifier;
import org.springframework.http.HttpHeaders;
import org.springframework.http.MediaType;
import io.swagger.v3.oas.annotations.enums.SecuritySchemeType;
import io.swagger.v3.oas.annotations.headers.Header;
import io.swagger.v3.oas.annotations.media.Content;
import io.swagger.v3.oas.annotations.media.Schema;
import io.swagger.v3.oas.annotations.responses.ApiResponse;
import io.swagger.v3.oas.annotations.responses.ApiResponses;
import io.swagger.v3.oas.annotations.security.SecurityRequirement;
import io.swagger.v3.oas.annotations.security.SecurityScheme;
import top.egon.cola.platform.tianquan.jianshen.admin.iam.role.domain.vo.RoleEditDetailVO;
import jakarta.validation.constraints.PositiveOrZero;
import org.springframework.security.core.annotation.AuthenticationPrincipal;
import org.springframework.web.bind.annotation.DeleteMapping;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PathVariable;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.PutMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.RestController;
import top.egon.cola.component.common.core.pojo.ResultRecord;
import io.swagger.v3.oas.annotations.Operation;
import io.swagger.v3.oas.annotations.tags.Tag;
import top.egon.cola.component.yuheng.openapi.annotation.EgonApiCatalog;
import top.egon.cola.component.yuheng.openapi.annotation.EgonGatewayPolicy;
import top.egon.cola.platform.tianquan.jianshen.admin.authorization.grant.roleinheritance.domain.dto.InheritanceCommandDTO;
import top.egon.cola.platform.tianquan.jianshen.admin.authorization.grant.roleinheritance.domain.dto.InheritanceRequestDTO;
import top.egon.cola.platform.tianquan.jianshen.admin.iam.role.domain.dto.CreateRoleCommandDTO;
import top.egon.cola.platform.tianquan.jianshen.admin.iam.role.domain.dto.CreateRoleRequestDTO;
import top.egon.cola.platform.tianquan.jianshen.admin.iam.role.domain.dto.UpdateRoleCommandDTO;
import top.egon.cola.platform.tianquan.jianshen.admin.iam.role.domain.dto.UpdateRoleRequestDTO;
import top.egon.cola.platform.tianquan.jianshen.admin.iam.role.domain.vo.RoleImpactVO;
import top.egon.cola.platform.tianquan.jianshen.admin.iam.role.domain.vo.RoleMutationResultVO;
import top.egon.cola.platform.tianquan.jianshen.admin.iam.role.domain.vo.RoleVO;
import top.egon.cola.platform.tianquan.jianshen.admin.iam.role.service.RoleFacade;
import top.egon.cola.platform.tianquan.jianshen.admin.shared.domain.DatabaseClock;
import top.egon.cola.platform.tianquan.jianshen.admin.shared.tenant.domain.TenantContext;
import top.egon.cola.platform.tianquan.jianshen.core.rule.Rbac3RuleViolation;
import top.egon.cola.platform.tianquan.jianshen.starter.security.CurrentRbac3User;
import top.egon.cola.platform.tianquan.jianshen.starter.security.Rbac3UserDetails;
import top.egon.cola.platform.tianquan.jianshen.contract.permission.annotation.RequiresPermissions;

import java.time.Instant;
import java.util.List;

/**
 * 类型 `RoleController` 位于当前包内，是类型，用于承载 `Role Permission Controller` 相关的职责、状态或契约；调用方通常通过其公开 API、Spring 装配或实现关系使用。
 * Type `RoleController` is a type in its package and carries the responsibility, state, or contract for `Role Permission Controller`; callers normally use it through its public API, Spring assembly, or implementation relationship.
 *
 * 语义与用法：将 `RoleController` 作为 `当前包` 的职责边界使用，优先依赖其已有构造、接口或 Spring 装配方式。
 * Semantics and usage: use `RoleController` as the responsibility boundary of `the current package`, following its existing construction, interface, or Spring-assembly mechanism.
 */
@Slf4j
@RestController("roleController")
@RequiredArgsConstructor(onConstructor_ = @Autowired)
@SecurityScheme(name = "bearerAuth", type = SecuritySchemeType.HTTP, scheme = "bearer", bearerFormat = "JWT")
@RequestMapping("/api/tianquan-jianshen/v1/iam/roles")
@Tag(name = "role-permission", description = "角色与权限接口组")
@EgonApiCatalog(
        businessDomainCode = "xingyuan",
        businessDomainName = "平台治理域",
        entityDomainCode = "tianquan-jianshen",
        entityDomainName = "RBAC3权限实体域",
        interfaceGroupCode = "iam"
)
public class RoleController {

    /**
     * 字段 `facade` 表示 `RoleController` 中与 `facade` 相关的状态、依赖、配置或结果（声明类型 `RoleFacade`）；其生命周期和取值含义由声明类型及所属对象共同确定。
     * Field `facade` stores the `facade`-related state, dependency, configuration, or result of `RoleController` (declared type `RoleFacade`); its lifecycle and value semantics are defined by its declared type and owning object.
     *
     * 含义与用法：读取、传递或更新 `facade` 时应保持 `RoleController` 的生命周期、不可变性和线程安全约束。
     * Meaning and usage: when reading, passing, or updating `facade`, preserve `RoleController`'s lifecycle, immutability, and thread-safety constraints.
     */
    @Qualifier("roleFacade")
    private final RoleFacade facade;
    /**
     * 字段 `databaseClock` 表示 `RoleController` 中与 `database Clock` 相关的状态、依赖、配置或结果（声明类型 `DatabaseClock`）；其生命周期和取值含义由声明类型及所属对象共同确定。
     * Field `databaseClock` stores the `database Clock`-related state, dependency, configuration, or result of `RoleController` (declared type `DatabaseClock`); its lifecycle and value semantics are defined by its declared type and owning object.
     *
     * 含义与用法：读取、传递或更新 `databaseClock` 时应保持 `RoleController` 的生命周期、不可变性和线程安全约束。
     * Meaning and usage: when reading, passing, or updating `databaseClock`, preserve `RoleController`'s lifecycle, immutability, and thread-safety constraints.
     */
    @Qualifier("jpaDatabaseClock")
    private final DatabaseClock databaseClock;

    @PermissionResource(key = "tianquan-jianshen.api.Role.roleEditDetail", type = ResourceType.API,
            labelPage = "tianquan-jianshen.permissions", labelKey = "api.Role.roleEditDetail")
    @GetMapping(value = "/{roleId}", produces = MediaType.APPLICATION_JSON_VALUE)
    @RequiresPermissions(codes = "system:role:update")
    @EgonGatewayPolicy(exposure = EgonGatewayPolicy.Exposure.EXTERNAL)
    @Operation(operationId = "tianquan-jianshen-role-edit-detail-v1", summary = "读取角色编辑详情",
            tags = {"tianquan-jianshen", "role"}, security = @SecurityRequirement(name = "bearerAuth"))
    @ApiResponses({
            @ApiResponse(responseCode = "200", description = "本租户角色原值和版本",
                    headers = @Header(name = "Cache-Control", description = "no-store")),
            @ApiResponse(responseCode = "400", description = "REQUEST_INVALID",
                    content = @Content(mediaType = MediaType.APPLICATION_JSON_VALUE,
                            schema = @Schema(implementation = ResultRecord.class))),
            @ApiResponse(responseCode = "401", description = "AUTHENTICATION_REQUIRED",
                    headers = @Header(name = "WWW-Authenticate", description = "Bearer"),
                    content = @Content(mediaType = MediaType.APPLICATION_JSON_VALUE,
                            schema = @Schema(implementation = RoleEditSecurityErrorVO.class))),
            @ApiResponse(responseCode = "403", description = "请求或角色更新权限被拒绝",
                    content = @Content(mediaType = MediaType.APPLICATION_JSON_VALUE,
                            schema = @Schema(anyOf = {RoleEditSecurityErrorVO.class, ResultRecord.class}))),
            @ApiResponse(responseCode = "404", description = "RESOURCE_NOT_FOUND",
                    content = @Content(mediaType = MediaType.APPLICATION_JSON_VALUE,
                            schema = @Schema(implementation = ResultRecord.class))),
            @ApiResponse(responseCode = "503", description = "安全审计交付或授权运行态不可用",
                    content = @Content(mediaType = MediaType.APPLICATION_JSON_VALUE,
                            schema = @Schema(anyOf = {RoleEditSecurityErrorVO.class, ResultRecord.class})))
    })
    public ResultRecord<RoleEditDetailVO> roleEditDetail(
            @PathVariable @Pattern(regexp = "^[1-9][0-9]{0,18}$") String roleId,
            HttpServletResponse response
    ) {
        response.setHeader(HttpHeaders.CACHE_CONTROL, "no-store");
        long numericRoleId = Long.parseLong(roleId);
        return ResultRecord.success(facade.roleEditDetail(
                TenantContext.requireCurrent().authenticatedTenantId(), numericRoleId));
    }

    /** OpenAPI view of the existing two-string response sent by the security chain. */
    public record RoleEditSecurityErrorVO(
            @Schema(requiredMode = Schema.RequiredMode.REQUIRED) String code,
            @Schema(requiredMode = Schema.RequiredMode.REQUIRED) String message
    ) { }

    /**
     * 方法 `roles` 按照 `RoleController` 的职责处理输入，完成 `roles` 操作并返回结果或产生声明的副作用；调用方应遵守参数和异常契约。
     * Method `roles` processes its inputs according to `RoleController`'s responsibility, performs the `roles` operation, and returns a result or declared side effect; callers must follow its parameter and exception contract.
     *
     * 用法：调用 `roles` 前准备符合契约的参数，并根据返回值、异常或副作用继续业务流程。
     * Usage: provide contract-compliant arguments before calling `roles`, then continue the business flow using its result, exception, or side effect.
     *
     * @param applicationId 输入参数 `applicationId`，用于确定本次操作的范围或内容；input value used to determine the operation's scope or content.
     * @return 操作产生的结果，其具体语义由返回类型和所属 API 定义；the result of the operation, whose exact semantics are defined by the return type and owning API.
     */
    @PermissionResource(key = "tianquan-jianshen.api.Role.roles", type = ResourceType.API,
            labelPage = "tianquan-jianshen.permissions", labelKey = "api.Role.roles")
    @GetMapping
    @RequiresPermissions(codes = "system:role:read")
    @Operation(
            operationId = "tianquan-jianshen-role-list-v1",
            summary = "查询租户角色",
            tags = {"tianquan-jianshen", "role"}
    )
    @EgonGatewayPolicy(
            exposure = EgonGatewayPolicy.Exposure.EXTERNAL
    )
    public ResultRecord<List<RoleVO>> roles(
            @RequestParam(required = false) String applicationId) {
        return ResultRecord.success(facade.roles(tenantId(), applicationId));
    }

    /**
     * 方法 `create` 按照 `RoleController` 的职责处理输入，完成 `create` 操作并返回结果或产生声明的副作用；调用方应遵守参数和异常契约。
     * Method `create` processes its inputs according to `RoleController`'s responsibility, performs the `create` operation, and returns a result or declared side effect; callers must follow its parameter and exception contract.
     *
     * 用法：调用 `create` 前准备符合契约的参数，并根据返回值、异常或副作用继续业务流程。
     * Usage: provide contract-compliant arguments before calling `create`, then continue the business flow using its result, exception, or side effect.
     *
     * @param request 输入参数 `request`，用于确定本次操作的范围或内容；input value used to determine the operation's scope or content.
     * @param principal 输入参数 `principal`，用于确定本次操作的范围或内容；input value used to determine the operation's scope or content.
     * @return 操作产生的结果，其具体语义由返回类型和所属 API 定义；the result of the operation, whose exact semantics are defined by the return type and owning API.
     */
    @PermissionResource(key = "tianquan-jianshen.api.Role.create", type = ResourceType.API,
            labelPage = "tianquan-jianshen.permissions", labelKey = "api.Role.create")
    @PostMapping
    @RequiresPermissions(codes = "system:role:create")
    @Operation(
            operationId = "tianquan-jianshen-role-create-v1",
            summary = "创建应用角色",
            tags = {"tianquan-jianshen", "role"}
    )
    @EgonGatewayPolicy(
            exposure = EgonGatewayPolicy.Exposure.EXTERNAL
    )
    public ResultRecord<RoleMutationResultVO> create(
            @Valid @RequestBody CreateRoleRequestDTO request
) {
        if (request.privileged() && !new CurrentRbac3User().require().hasPermission("system:platform:admin")) {
            throw new Rbac3RuleViolation("PRIVILEGED_ROLE_MANAGEMENT_DENIED");
        }
        return ResultRecord.success(facade.createRole(new CreateRoleCommandDTO(
                tenantId(),
                request.applicationId(),
                request.roleCode(),
                request.roleName(),
                request.roleType(),
                request.riskLevel(),
                request.privileged(),
                request.landingRouteId(),
                request.landingPriority(),
                request.maximumAssignmentDays(),
                new CurrentRbac3User().require().rbac3UserId()),
                databaseClock.transactionNow()));
    }

    /**
     * 方法 `update` 按照 `RoleController` 的职责处理输入，完成 `update` 操作并返回结果或产生声明的副作用；调用方应遵守参数和异常契约。
     * Method `update` processes its inputs according to `RoleController`'s responsibility, performs the `update` operation, and returns a result or declared side effect; callers must follow its parameter and exception contract.
     *
     * 用法：调用 `update` 前准备符合契约的参数，并根据返回值、异常或副作用继续业务流程。
     * Usage: provide contract-compliant arguments before calling `update`, then continue the business flow using its result, exception, or side effect.
     *
     * @param roleId 输入参数 `roleId`，用于确定本次操作的范围或内容；input value used to determine the operation's scope or content.
     * @param request 输入参数 `request`，用于确定本次操作的范围或内容；input value used to determine the operation's scope or content.
     * @param principal 输入参数 `principal`，用于确定本次操作的范围或内容；input value used to determine the operation's scope or content.
     * @return 操作产生的结果，其具体语义由返回类型和所属 API 定义；the result of the operation, whose exact semantics are defined by the return type and owning API.
     */
    @PermissionResource(key = "tianquan-jianshen.api.Role.update", type = ResourceType.API,
            labelPage = "tianquan-jianshen.permissions", labelKey = "api.Role.update")
    @PutMapping("/{roleId}")
    @RequiresPermissions(codes = "system:role:update")
    @Operation(
            operationId = "tianquan-jianshen-role-update-v1",
            summary = "更新角色可变属性",
            tags = {"tianquan-jianshen", "role"}
    )
    @EgonGatewayPolicy(
            exposure = EgonGatewayPolicy.Exposure.EXTERNAL
    )
    public ResultRecord<RoleMutationResultVO> update(
            @PathVariable String roleId,
            @Valid @RequestBody UpdateRoleRequestDTO request
) {
        return ResultRecord.success(facade.updateRole(new UpdateRoleCommandDTO(
                tenantId(),
                roleId,
                request.roleName(),
                request.status(),
                request.landingRouteId(),
                request.landingPriority(),
                request.maximumAssignmentDays(),
                request.expectedRoleVersion(),
                new CurrentRbac3User().require().rbac3UserId()),
                databaseClock.transactionNow()));
    }

    /**
     * 方法 `addInheritance` 按照 `RoleController` 的职责处理输入，完成 `add Inheritance` 操作并返回结果或产生声明的副作用；调用方应遵守参数和异常契约。
     * Method `addInheritance` processes its inputs according to `RoleController`'s responsibility, performs the `add Inheritance` operation, and returns a result or declared side effect; callers must follow its parameter and exception contract.
     *
     * 用法：调用 `addInheritance` 前准备符合契约的参数，并根据返回值、异常或副作用继续业务流程。
     * Usage: provide contract-compliant arguments before calling `addInheritance`, then continue the business flow using its result, exception, or side effect.
     *
     * @param roleId 输入参数 `roleId`，用于确定本次操作的范围或内容；input value used to determine the operation's scope or content.
     * @param request 输入参数 `request`，用于确定本次操作的范围或内容；input value used to determine the operation's scope or content.
     * @param principal 输入参数 `principal`，用于确定本次操作的范围或内容；input value used to determine the operation's scope or content.
     * @return 操作产生的结果，其具体语义由返回类型和所属 API 定义；the result of the operation, whose exact semantics are defined by the return type and owning API.
     */
    @PermissionResource(key = "tianquan-jianshen.api.Role.addInheritance", type = ResourceType.API,
            labelPage = "tianquan-jianshen.permissions", labelKey = "api.Role.addInheritance")
    @PostMapping("/{roleId}/inheritances")
    @RequiresPermissions(codes = "system:role-inheritance:manage")
    @Operation(
            operationId = "tianquan-jianshen-role-inheritance-add-v1",
            summary = "新增角色继承边并重建闭包",
            tags = {"tianquan-jianshen", "role", "inheritance"}
    )
    @EgonGatewayPolicy(
            exposure = EgonGatewayPolicy.Exposure.EXTERNAL
    )
    public ResultRecord<RoleImpactVO> addInheritance(
            @PathVariable String roleId,
            @Valid @RequestBody InheritanceRequestDTO request
) {
        facade.addInheritance(new InheritanceCommandDTO(
                tenantId(), request.applicationId(), roleId, request.juniorRoleId(),
                request.expectedRoleVersion(), new CurrentRbac3User().require().rbac3UserId()));
        return ResultRecord.success(facade.impact(tenantId(), roleId));
    }

    /**
     * 方法 `removeInheritance` 按照 `RoleController` 的职责处理输入，完成 `remove Inheritance` 操作并返回结果或产生声明的副作用；调用方应遵守参数和异常契约。
     * Method `removeInheritance` processes its inputs according to `RoleController`'s responsibility, performs the `remove Inheritance` operation, and returns a result or declared side effect; callers must follow its parameter and exception contract.
     *
     * 用法：调用 `removeInheritance` 前准备符合契约的参数，并根据返回值、异常或副作用继续业务流程。
     * Usage: provide contract-compliant arguments before calling `removeInheritance`, then continue the business flow using its result, exception, or side effect.
     *
     * @param roleId 输入参数 `roleId`，用于确定本次操作的范围或内容；input value used to determine the operation's scope or content.
     * @param juniorRoleId 输入参数 `juniorRoleId`，用于确定本次操作的范围或内容；input value used to determine the operation's scope or content.
     * @param applicationId 输入参数 `applicationId`，用于确定本次操作的范围或内容；input value used to determine the operation's scope or content.
     * @param expectedRoleVersion 输入参数 `expectedRoleVersion`，用于确定本次操作的范围或内容；input value used to determine the operation's scope or content.
     * @param principal 输入参数 `principal`，用于确定本次操作的范围或内容；input value used to determine the operation's scope or content.
     * @return 操作产生的结果，其具体语义由返回类型和所属 API 定义；the result of the operation, whose exact semantics are defined by the return type and owning API.
     */
    @PermissionResource(key = "tianquan-jianshen.api.Role.removeInheritance", type = ResourceType.API,
            labelPage = "tianquan-jianshen.permissions", labelKey = "api.Role.removeInheritance")
    @DeleteMapping("/{roleId}/inheritances/{juniorRoleId}")
    @RequiresPermissions(codes = "system:role-inheritance:manage")
    @Operation(
            operationId = "tianquan-jianshen-role-inheritance-remove-v1",
            summary = "删除角色继承边并重建闭包",
            tags = {"tianquan-jianshen", "role", "inheritance"}
    )
    @EgonGatewayPolicy(
            exposure = EgonGatewayPolicy.Exposure.EXTERNAL
    )
    public ResultRecord<RoleImpactVO> removeInheritance(
            @PathVariable String roleId,
            @PathVariable String juniorRoleId,
            @RequestParam String applicationId,
            @RequestParam @PositiveOrZero long expectedRoleVersion
) {
        facade.removeInheritance(new InheritanceCommandDTO(
                tenantId(), applicationId, roleId, juniorRoleId,
                expectedRoleVersion, new CurrentRbac3User().require().rbac3UserId()));
        return ResultRecord.success(facade.impact(tenantId(), roleId));
    }

    /**
     * 方法 `impact` 按照 `RoleController` 的职责处理输入，完成 `impact` 操作并返回结果或产生声明的副作用；调用方应遵守参数和异常契约。
     * Method `impact` processes its inputs according to `RoleController`'s responsibility, performs the `impact` operation, and returns a result or declared side effect; callers must follow its parameter and exception contract.
     *
     * 用法：调用 `impact` 前准备符合契约的参数，并根据返回值、异常或副作用继续业务流程。
     * Usage: provide contract-compliant arguments before calling `impact`, then continue the business flow using its result, exception, or side effect.
     *
     * @param roleId 输入参数 `roleId`，用于确定本次操作的范围或内容；input value used to determine the operation's scope or content.
     * @return 操作产生的结果，其具体语义由返回类型和所属 API 定义；the result of the operation, whose exact semantics are defined by the return type and owning API.
     */
    @PermissionResource(key = "tianquan-jianshen.api.Role.impact", type = ResourceType.API,
            labelPage = "tianquan-jianshen.permissions", labelKey = "api.Role.impact")
    @GetMapping("/{roleId}/impact-analysis")
    @RequiresPermissions(codes = "system:role:read")
    @Operation(
            operationId = "tianquan-jianshen-role-impact-v1",
            summary = "分析角色族与权限扩张影响",
            tags = {"tianquan-jianshen", "role", "impact"}
    )
    @EgonGatewayPolicy(
            exposure = EgonGatewayPolicy.Exposure.EXTERNAL
    )
    public ResultRecord<RoleImpactVO> impact(@PathVariable String roleId) {
        return ResultRecord.success(facade.impact(tenantId(), roleId));
    }

    /**
     * 方法 `tenantId` 按照 `RoleController` 的职责处理输入，完成 `tenant Id` 操作并返回结果或产生声明的副作用；调用方应遵守参数和异常契约。
     * Method `tenantId` processes its inputs according to `RoleController`'s responsibility, performs the `tenant Id` operation, and returns a result or declared side effect; callers must follow its parameter and exception contract.
     *
     * 用法：调用 `tenantId` 前准备符合契约的参数，并根据返回值、异常或副作用继续业务流程。
     * Usage: provide contract-compliant arguments before calling `tenantId`, then continue the business flow using its result, exception, or side effect.
     *
     * @return 操作产生的结果，其具体语义由返回类型和所属 API 定义；the result of the operation, whose exact semantics are defined by the return type and owning API.
     */
    private static String tenantId() {
        return TenantContext.requireCurrent().effectiveTenantId();
    }




    }
