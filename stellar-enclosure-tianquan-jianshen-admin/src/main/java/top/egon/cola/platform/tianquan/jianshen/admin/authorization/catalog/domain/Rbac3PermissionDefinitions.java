package top.egon.cola.platform.tianquan.jianshen.admin.authorization.catalog.domain;

import top.egon.cola.platform.tianquan.jianshen.contract.permission.annotation.PermissionDefinition;
import top.egon.cola.platform.tianquan.jianshen.contract.permission.annotation.PermissionMessage;
import top.egon.cola.platform.tianquan.jianshen.contract.permission.annotation.LocalizedText;

/** Source-owned administrative capabilities; publishing definitions never grants a role. */
@PermissionDefinition(code = "system:about:read", meaning = "Read authorization module information within the verified tenant and application boundary",
        labelPage = "tianquan-jianshen.permissions", labelKey = "permission.about.read")
@PermissionDefinition(code = "system:application:manage", meaning = "Manage tenant applications within the verified tenant and application boundary",
        labelPage = "tianquan-jianshen.permissions", labelKey = "permission.application.manage")
@PermissionDefinition(code = "system:application:read", meaning = "Read tenant applications within the verified tenant and application boundary",
        labelPage = "tianquan-jianshen.permissions", labelKey = "permission.application.read")
@PermissionDefinition(code = "system:audit:read", meaning = "Read audit records within the verified tenant and application boundary",
        labelPage = "tianquan-jianshen.permissions", labelKey = "permission.audit.read")
@PermissionDefinition(code = "system:authorization-constraint:manage", meaning = "Manage authorization constraints within the verified tenant and application boundary",
        labelPage = "tianquan-jianshen.permissions", labelKey = "permission.authorization-constraint.manage")
@PermissionDefinition(code = "system:authorization-constraint:read", meaning = "Read authorization constraints within the verified tenant and application boundary",
        labelPage = "tianquan-jianshen.permissions", labelKey = "permission.authorization-constraint.read")
@PermissionDefinition(code = "system:authorization-runtime:operate", meaning = "Operate authorization runtime within the verified tenant and application boundary",
        labelPage = "tianquan-jianshen.permissions", labelKey = "permission.authorization-runtime.operate")
@PermissionDefinition(code = "system:authorization-runtime:read", meaning = "Read authorization runtime within the verified tenant and application boundary",
        labelPage = "tianquan-jianshen.permissions", labelKey = "permission.authorization-runtime.read")
@PermissionDefinition(code = "system:authorization-simulation:execute", meaning = "Execute authorization simulations within the verified tenant and application boundary",
        labelPage = "tianquan-jianshen.permissions", labelKey = "permission.authorization-simulation.execute")
@PermissionDefinition(code = "system:business:read", meaning = "Read business catalogs within the verified tenant and application boundary",
        labelPage = "tianquan-jianshen.permissions", labelKey = "permission.business.read")
@PermissionDefinition(code = "system:data-rule:manage", meaning = "Manage typed data rules within the verified tenant and application boundary",
        labelPage = "tianquan-jianshen.permissions", labelKey = "permission.data-rule.manage")
@PermissionDefinition(code = "system:data-rule:read", meaning = "Read typed data rules within the verified tenant and application boundary",
        labelPage = "tianquan-jianshen.permissions", labelKey = "permission.data-rule.read")
@PermissionDefinition(code = "system:directory-snapshot:read", meaning = "Read directory snapshots within the verified tenant and application boundary",
        labelPage = "tianquan-jianshen.permissions", labelKey = "permission.directory-snapshot.read")
@PermissionDefinition(code = "system:directory:read", meaning = "Read organization directories within the verified tenant and application boundary",
        labelPage = "tianquan-jianshen.permissions", labelKey = "permission.directory.read")
@PermissionDefinition(code = "system:directory:sync", meaning = "Synchronize organization directories within the verified tenant and application boundary",
        labelPage = "tianquan-jianshen.permissions", labelKey = "permission.directory.sync")
@PermissionDefinition(code = "system:field-definition:read", meaning = "Read historical field definitions within the verified tenant and application boundary",
        labelPage = "tianquan-jianshen.permissions", labelKey = "permission.field-definition.read")
@PermissionDefinition(code = "system:field-rule:read", meaning = "Read historical field rules within the verified tenant and application boundary",
        labelPage = "tianquan-jianshen.permissions", labelKey = "permission.field-rule.read")
@PermissionDefinition(code = "system:management-policy:manage", meaning = "Manage delegated management policies within the verified tenant and application boundary",
        labelPage = "tianquan-jianshen.permissions", labelKey = "permission.management-policy.manage")
@PermissionDefinition(code = "system:management-policy:read", meaning = "Read delegated management policies within the verified tenant and application boundary",
        labelPage = "tianquan-jianshen.permissions", labelKey = "permission.management-policy.read")
@PermissionDefinition(code = "system:operation-sod:manage", meaning = "Manage operation separation rules within the verified tenant and application boundary",
        labelPage = "tianquan-jianshen.permissions", labelKey = "permission.operation-sod.manage")
@PermissionDefinition(code = "system:operation-sod:read", meaning = "Read operation separation rules within the verified tenant and application boundary",
        labelPage = "tianquan-jianshen.permissions", labelKey = "permission.operation-sod.read")
@PermissionDefinition(code = "system:organization:manage", meaning = "Manage organizations within the verified tenant and application boundary",
        labelPage = "tianquan-jianshen.permissions", labelKey = "permission.organization.manage")
@PermissionDefinition(code = "system:organization:read", meaning = "Read organizations within the verified tenant and application boundary",
        labelPage = "tianquan-jianshen.permissions", labelKey = "permission.organization.read")
@PermissionDefinition(code = "system:platform:admin", meaning = "Admin platform within the verified tenant and application boundary",
        labelPage = "tianquan-jianshen.permissions", labelKey = "permission.platform.admin")
@PermissionDefinition(code = "system:position:manage", meaning = "Manage positions within the verified tenant and application boundary",
        labelPage = "tianquan-jianshen.permissions", labelKey = "permission.position.manage")
@PermissionDefinition(code = "system:position:read", meaning = "Read positions within the verified tenant and application boundary",
        labelPage = "tianquan-jianshen.permissions", labelKey = "permission.position.read")
@PermissionDefinition(code = "system:resource:archive", meaning = "Archive historical resources within the verified tenant and application boundary",
        labelPage = "tianquan-jianshen.permissions", labelKey = "permission.resource.archive")
@PermissionDefinition(code = "system:resource:read", meaning = "Read historical resources within the verified tenant and application boundary",
        labelPage = "tianquan-jianshen.permissions", labelKey = "permission.resource.read")
@PermissionDefinition(code = "system:role-activation:read", meaning = "Read active roles within the verified tenant and application boundary",
        labelPage = "tianquan-jianshen.permissions", labelKey = "permission.role-activation.read")
@PermissionDefinition(code = "system:role-activation:use", meaning = "Change active roles within the verified tenant and application boundary",
        labelPage = "tianquan-jianshen.permissions", labelKey = "permission.role-activation.use")
@PermissionDefinition(code = "system:role-assignment:manage", meaning = "Manage user role assignments within the verified tenant and application boundary",
        labelPage = "tianquan-jianshen.permissions", labelKey = "permission.role-assignment.manage")
@PermissionDefinition(code = "system:role-assignment:read", meaning = "Read user role assignments within the verified tenant and application boundary",
        labelPage = "tianquan-jianshen.permissions", labelKey = "permission.role-assignment.read")
@PermissionDefinition(code = "system:role-inheritance:manage", meaning = "Manage role inheritance within the verified tenant and application boundary",
        labelPage = "tianquan-jianshen.permissions", labelKey = "permission.role-inheritance.manage")
@PermissionDefinition(code = "system:role:create", meaning = "Create roles within the verified tenant and application boundary",
        labelPage = "tianquan-jianshen.permissions", labelKey = "permission.role.create")
@PermissionDefinition(code = "system:role:read", meaning = "Read roles within the verified tenant and application boundary",
        labelPage = "tianquan-jianshen.permissions", labelKey = "permission.role.read")
@PermissionDefinition(code = "system:role:update", meaning = "Update roles within the verified tenant and application boundary",
        labelPage = "tianquan-jianshen.permissions", labelKey = "permission.role.update")
@PermissionDefinition(code = "system:user-application-access:read", meaning = "Read user application access within the verified tenant and application boundary",
        labelPage = "tianquan-jianshen.permissions", labelKey = "permission.user-application-access.read")
@PermissionDefinition(code = "system:user-business-access:manage", meaning = "Manage user business access within the verified tenant and application boundary",
        labelPage = "tianquan-jianshen.permissions", labelKey = "permission.user-business-access.manage")
@PermissionDefinition(code = "system:user-business-access:read", meaning = "Read user business access within the verified tenant and application boundary",
        labelPage = "tianquan-jianshen.permissions", labelKey = "permission.user-business-access.read")
@PermissionDefinition(code = "system:user-organization:manage", meaning = "Manage user organization assignments within the verified tenant and application boundary",
        labelPage = "tianquan-jianshen.permissions", labelKey = "permission.user-organization.manage")
@PermissionDefinition(code = "system:user-organization:read", meaning = "Read user organization assignments within the verified tenant and application boundary",
        labelPage = "tianquan-jianshen.permissions", labelKey = "permission.user-organization.read")
@PermissionDefinition(code = "system:user-position:manage", meaning = "Manage user position assignments within the verified tenant and application boundary",
        labelPage = "tianquan-jianshen.permissions", labelKey = "permission.user-position.manage")
@PermissionDefinition(code = "system:user-position:read", meaning = "Read user position assignments within the verified tenant and application boundary",
        labelPage = "tianquan-jianshen.permissions", labelKey = "permission.user-position.read")
@PermissionDefinition(code = "system:user-status:manage", meaning = "Manage user status within the verified tenant and application boundary",
        labelPage = "tianquan-jianshen.permissions", labelKey = "permission.user-status.manage")
@PermissionDefinition(code = "system:user:manage", meaning = "Manage users within the verified tenant and application boundary",
        labelPage = "tianquan-jianshen.permissions", labelKey = "permission.user.manage")
@PermissionDefinition(code = "system:user:read", meaning = "Read users within the verified tenant and application boundary",
        labelPage = "tianquan-jianshen.permissions", labelKey = "permission.user.read")
@PermissionMessage(pageCode = "tianquan-jianshen.permissions", key = "api.Application.admit", defaultLocale = "zh-CN",
        defaults = @LocalizedText(locale = "zh-CN", text = "将 Tianshu 应用纳入租户授权范围"))
@PermissionMessage(pageCode = "tianquan-jianshen.permissions", key = "api.Application.application", defaultLocale = "zh-CN",
        defaults = @LocalizedText(locale = "zh-CN", text = "查询租户应用授权范围详情"))
@PermissionMessage(pageCode = "tianquan-jianshen.permissions", key = "api.Application.applications", defaultLocale = "zh-CN",
        defaults = @LocalizedText(locale = "zh-CN", text = "查询租户应用授权范围"))
@PermissionMessage(pageCode = "tianquan-jianshen.permissions", key = "api.Application.changeStatus", defaultLocale = "zh-CN",
        defaults = @LocalizedText(locale = "zh-CN", text = "变更租户应用授权范围状态"))
@PermissionMessage(pageCode = "tianquan-jianshen.permissions", key = "api.Application.remove", defaultLocale = "zh-CN",
        defaults = @LocalizedText(locale = "zh-CN", text = "移除无依赖的租户应用授权范围"))
@PermissionMessage(pageCode = "tianquan-jianshen.permissions", key = "api.ApplicationResource.applications", defaultLocale = "zh-CN",
        defaults = @LocalizedText(locale = "zh-CN", text = "查询租户应用"))
@PermissionMessage(pageCode = "tianquan-jianshen.permissions", key = "api.ApplicationResource.archive", defaultLocale = "zh-CN",
        defaults = @LocalizedText(locale = "zh-CN", text = "归档已失效资源"))
@PermissionMessage(pageCode = "tianquan-jianshen.permissions", key = "api.ApplicationResource.fields", defaultLocale = "zh-CN",
        defaults = @LocalizedText(locale = "zh-CN", text = "查询应用字段定义"))
@PermissionMessage(pageCode = "tianquan-jianshen.permissions", key = "api.ApplicationResource.resourceFields", defaultLocale = "zh-CN",
        defaults = @LocalizedText(locale = "zh-CN", text = "查询资源字段定义"))
@PermissionMessage(pageCode = "tianquan-jianshen.permissions", key = "api.ApplicationResource.resources", defaultLocale = "zh-CN",
        defaults = @LocalizedText(locale = "zh-CN", text = "查询应用资源"))
@PermissionMessage(pageCode = "tianquan-jianshen.permissions", key = "api.Assignment.assign", defaultLocale = "zh-CN",
        defaults = @LocalizedText(locale = "zh-CN", text = "按完整委托策略创建角色任职"))
@PermissionMessage(pageCode = "tianquan-jianshen.permissions", key = "api.Assignment.assignments", defaultLocale = "zh-CN",
        defaults = @LocalizedText(locale = "zh-CN", text = "查询用户角色任职及历史状态"))
@PermissionMessage(pageCode = "tianquan-jianshen.permissions", key = "api.Assignment.resume", defaultLocale = "zh-CN",
        defaults = @LocalizedText(locale = "zh-CN", text = "恢复角色任职"))
@PermissionMessage(pageCode = "tianquan-jianshen.permissions", key = "api.Assignment.revoke", defaultLocale = "zh-CN",
        defaults = @LocalizedText(locale = "zh-CN", text = "撤销角色任职并保留历史"))
@PermissionMessage(pageCode = "tianquan-jianshen.permissions", key = "api.Assignment.suspend", defaultLocale = "zh-CN",
        defaults = @LocalizedText(locale = "zh-CN", text = "暂停角色任职"))
@PermissionMessage(pageCode = "tianquan-jianshen.permissions", key = "api.Audit.auditLogs", defaultLocale = "zh-CN",
        defaults = @LocalizedText(locale = "zh-CN", text = "按租户和精确过滤条件游标查询审计"))
@PermissionMessage(pageCode = "tianquan-jianshen.permissions", key = "api.AuthorizationSimulation.simulate", defaultLocale = "zh-CN",
        defaults = @LocalizedText(locale = "zh-CN", text = "基于一致快照执行无业务副作用的授权模拟"))
@PermissionMessage(pageCode = "tianquan-jianshen.permissions", key = "api.AuthorizationSimulation.simulateRoleChangeImpact", defaultLocale = "zh-CN",
        defaults = @LocalizedText(locale = "zh-CN", text = "查询带策略版本和证据校验和的角色变更影响"))
@PermissionMessage(pageCode = "tianquan-jianshen.permissions", key = "api.BusinessCatalog.applications", defaultLocale = "zh-CN",
        defaults = @LocalizedText(locale = "zh-CN", text = "查询 Tianshu 业务域下的应用目录"))
@PermissionMessage(pageCode = "tianquan-jianshen.permissions", key = "api.BusinessCatalog.businesses", defaultLocale = "zh-CN",
        defaults = @LocalizedText(locale = "zh-CN", text = "查询 Tianshu 业务域目录"))
@PermissionMessage(pageCode = "tianquan-jianshen.permissions", key = "api.Constraint.cardinality", defaultLocale = "zh-CN",
        defaults = @LocalizedText(locale = "zh-CN", text = "配置角色容量"))
@PermissionMessage(pageCode = "tianquan-jianshen.permissions", key = "api.Constraint.createDataRule", defaultLocale = "zh-CN",
        defaults = @LocalizedText(locale = "zh-CN", text = "创建类型化数据规则"))
@PermissionMessage(pageCode = "tianquan-jianshen.permissions", key = "api.Constraint.createOperationSodRule", defaultLocale = "zh-CN",
        defaults = @LocalizedText(locale = "zh-CN", text = "创建同对象职责分离规则"))
@PermissionMessage(pageCode = "tianquan-jianshen.permissions", key = "api.Constraint.createSodSet", defaultLocale = "zh-CN",
        defaults = @LocalizedText(locale = "zh-CN", text = "创建SSD或DSD集合"))
@PermissionMessage(pageCode = "tianquan-jianshen.permissions", key = "api.Constraint.dataRules", defaultLocale = "zh-CN",
        defaults = @LocalizedText(locale = "zh-CN", text = "查询数据规则"))
@PermissionMessage(pageCode = "tianquan-jianshen.permissions", key = "api.Constraint.fieldRules", defaultLocale = "zh-CN",
        defaults = @LocalizedText(locale = "zh-CN", text = "查询字段规则"))
@PermissionMessage(pageCode = "tianquan-jianshen.permissions", key = "api.Constraint.operationSodRules", defaultLocale = "zh-CN",
        defaults = @LocalizedText(locale = "zh-CN", text = "查询同对象职责分离规则"))
@PermissionMessage(pageCode = "tianquan-jianshen.permissions", key = "api.Constraint.prerequisites", defaultLocale = "zh-CN",
        defaults = @LocalizedText(locale = "zh-CN", text = "替换角色前置条件组"))
@PermissionMessage(pageCode = "tianquan-jianshen.permissions", key = "api.Constraint.sodSets", defaultLocale = "zh-CN",
        defaults = @LocalizedText(locale = "zh-CN", text = "查询SSD和DSD集合"))
@PermissionMessage(pageCode = "tianquan-jianshen.permissions", key = "api.Constraint.updateDataRule", defaultLocale = "zh-CN",
        defaults = @LocalizedText(locale = "zh-CN", text = "更新类型化数据规则"))
@PermissionMessage(pageCode = "tianquan-jianshen.permissions", key = "api.Constraint.updateOperationSodRule", defaultLocale = "zh-CN",
        defaults = @LocalizedText(locale = "zh-CN", text = "更新同对象职责分离规则"))
@PermissionMessage(pageCode = "tianquan-jianshen.permissions", key = "api.Constraint.updateSodSet", defaultLocale = "zh-CN",
        defaults = @LocalizedText(locale = "zh-CN", text = "更新SSD或DSD集合"))
@PermissionMessage(pageCode = "tianquan-jianshen.permissions", key = "api.Directory.orgUnits", defaultLocale = "zh-CN",
        defaults = @LocalizedText(locale = "zh-CN", text = "查询组织单元"))
@PermissionMessage(pageCode = "tianquan-jianshen.permissions", key = "api.Directory.positions", defaultLocale = "zh-CN",
        defaults = @LocalizedText(locale = "zh-CN", text = "查询岗位"))
@PermissionMessage(pageCode = "tianquan-jianshen.permissions", key = "api.Directory.snapshot", defaultLocale = "zh-CN",
        defaults = @LocalizedText(locale = "zh-CN", text = "读取不可变目录快照回执"))
@PermissionMessage(pageCode = "tianquan-jianshen.permissions", key = "api.Directory.submit", defaultLocale = "zh-CN",
        defaults = @LocalizedText(locale = "zh-CN", text = "提交单调递增的目录快照"))
@PermissionMessage(pageCode = "tianquan-jianshen.permissions", key = "api.InternalAuthorization.currentPolicy", defaultLocale = "zh-CN",
        defaults = @LocalizedText(locale = "zh-CN", text = "InternalAuthorization currentPolicy"))
@PermissionMessage(pageCode = "tianquan-jianshen.permissions", key = "api.InternalAuthorization.currentSnapshot", defaultLocale = "zh-CN",
        defaults = @LocalizedText(locale = "zh-CN", text = "按已验证用户身份读取系统授权快照"))
@PermissionMessage(pageCode = "tianquan-jianshen.permissions", key = "api.InternalAuthorization.decide", defaultLocale = "zh-CN",
        defaults = @LocalizedText(locale = "zh-CN", text = "使用已验证用户身份执行类型化授权决策"))
@PermissionMessage(pageCode = "tianquan-jianshen.permissions", key = "api.InternalAuthorization.decideResourceAccess", defaultLocale = "zh-CN",
        defaults = @LocalizedText(locale = "zh-CN", text = "判定已验证用户是否具备应用入口权限"))
@PermissionMessage(pageCode = "tianquan-jianshen.permissions", key = "api.InternalAuthorization.verifyFence", defaultLocale = "zh-CN",
        defaults = @LocalizedText(locale = "zh-CN", text = "校验用户授权传播 Fence"))
@PermissionMessage(pageCode = "tianquan-jianshen.permissions", key = "api.ManagementPolicy.capabilities", defaultLocale = "zh-CN",
        defaults = @LocalizedText(locale = "zh-CN", text = "查询当前操作者委托管理能力"))
@PermissionMessage(pageCode = "tianquan-jianshen.permissions", key = "api.ManagementPolicy.create", defaultLocale = "zh-CN",
        defaults = @LocalizedText(locale = "zh-CN", text = "创建完整委托管理策略"))
@PermissionMessage(pageCode = "tianquan-jianshen.permissions", key = "api.ManagementPolicy.disable", defaultLocale = "zh-CN",
        defaults = @LocalizedText(locale = "zh-CN", text = "禁用委托管理策略并保留历史明细"))
@PermissionMessage(pageCode = "tianquan-jianshen.permissions", key = "api.ManagementPolicy.manageableRoles", defaultLocale = "zh-CN",
        defaults = @LocalizedText(locale = "zh-CN", text = "按委托白名单搜索可管理角色根"))
@PermissionMessage(pageCode = "tianquan-jianshen.permissions", key = "api.ManagementPolicy.manageableUsers", defaultLocale = "zh-CN",
        defaults = @LocalizedText(locale = "zh-CN", text = "按委托范围搜索可管理用户"))
@PermissionMessage(pageCode = "tianquan-jianshen.permissions", key = "api.ManagementPolicy.policies", defaultLocale = "zh-CN",
        defaults = @LocalizedText(locale = "zh-CN", text = "查询完整委托管理策略"))
@PermissionMessage(pageCode = "tianquan-jianshen.permissions", key = "api.ManagementPolicy.policy", defaultLocale = "zh-CN",
        defaults = @LocalizedText(locale = "zh-CN", text = "读取委托管理策略完整聚合"))
@PermissionMessage(pageCode = "tianquan-jianshen.permissions", key = "api.ManagementPolicy.update", defaultLocale = "zh-CN",
        defaults = @LocalizedText(locale = "zh-CN", text = "按版本完整替换委托管理策略"))
@PermissionMessage(pageCode = "tianquan-jianshen.permissions", key = "api.Organization.create", defaultLocale = "zh-CN",
        defaults = @LocalizedText(locale = "zh-CN", text = "创建手工组织"))
@PermissionMessage(pageCode = "tianquan-jianshen.permissions", key = "api.Organization.list", defaultLocale = "zh-CN",
        defaults = @LocalizedText(locale = "zh-CN", text = "查询手工组织"))
@PermissionMessage(pageCode = "tianquan-jianshen.permissions", key = "api.Organization.remove", defaultLocale = "zh-CN",
        defaults = @LocalizedText(locale = "zh-CN", text = "停用手工组织"))
@PermissionMessage(pageCode = "tianquan-jianshen.permissions", key = "api.Organization.update", defaultLocale = "zh-CN",
        defaults = @LocalizedText(locale = "zh-CN", text = "更新或移动手工组织"))
@PermissionMessage(pageCode = "tianquan-jianshen.permissions", key = "api.Participation.conflicts", defaultLocale = "zh-CN",
        defaults = @LocalizedText(locale = "zh-CN", text = "查询同一业务对象的职责冲突证据"))
@PermissionMessage(pageCode = "tianquan-jianshen.permissions", key = "api.Participation.record", defaultLocale = "zh-CN",
        defaults = @LocalizedText(locale = "zh-CN", text = "幂等追加业务对象参与事实"))
@PermissionMessage(pageCode = "tianquan-jianshen.permissions", key = "api.Position.create", defaultLocale = "zh-CN",
        defaults = @LocalizedText(locale = "zh-CN", text = "创建手工岗位"))
@PermissionMessage(pageCode = "tianquan-jianshen.permissions", key = "api.Position.list", defaultLocale = "zh-CN",
        defaults = @LocalizedText(locale = "zh-CN", text = "查询手工岗位"))
@PermissionMessage(pageCode = "tianquan-jianshen.permissions", key = "api.Position.remove", defaultLocale = "zh-CN",
        defaults = @LocalizedText(locale = "zh-CN", text = "停用手工岗位"))
@PermissionMessage(pageCode = "tianquan-jianshen.permissions", key = "api.Position.update", defaultLocale = "zh-CN",
        defaults = @LocalizedText(locale = "zh-CN", text = "更新手工岗位"))
@PermissionMessage(pageCode = "tianquan-jianshen.permissions", key = "api.Rbac3About.about", defaultLocale = "zh-CN",
        defaults = @LocalizedText(locale = "zh-CN", text = "查询当前授权上下文"))
@PermissionMessage(pageCode = "tianquan-jianshen.permissions", key = "api.Role.addInheritance", defaultLocale = "zh-CN",
        defaults = @LocalizedText(locale = "zh-CN", text = "新增角色继承边并重建闭包"))
@PermissionMessage(pageCode = "tianquan-jianshen.permissions", key = "api.Role.create", defaultLocale = "zh-CN",
        defaults = @LocalizedText(locale = "zh-CN", text = "创建应用角色"))
@PermissionMessage(pageCode = "tianquan-jianshen.permissions", key = "api.Role.impact", defaultLocale = "zh-CN",
        defaults = @LocalizedText(locale = "zh-CN", text = "分析角色族与权限扩张影响"))
@PermissionMessage(pageCode = "tianquan-jianshen.permissions", key = "api.Role.removeInheritance", defaultLocale = "zh-CN",
        defaults = @LocalizedText(locale = "zh-CN", text = "删除角色继承边并重建闭包"))
@PermissionMessage(pageCode = "tianquan-jianshen.permissions", key = "api.Role.roles", defaultLocale = "zh-CN",
        defaults = @LocalizedText(locale = "zh-CN", text = "查询租户角色"))
@PermissionMessage(pageCode = "tianquan-jianshen.permissions", key = "api.Role.update", defaultLocale = "zh-CN",
        defaults = @LocalizedText(locale = "zh-CN", text = "更新角色可变属性"))
@PermissionMessage(pageCode = "tianquan-jianshen.permissions", key = "api.RoleActivation.candidates", defaultLocale = "zh-CN",
        defaults = @LocalizedText(locale = "zh-CN", text = "查询当前会话可激活的规范根角色"))
@PermissionMessage(pageCode = "tianquan-jianshen.permissions", key = "api.RoleActivation.current", defaultLocale = "zh-CN",
        defaults = @LocalizedText(locale = "zh-CN", text = "查询当前会话已激活的规范根角色"))
@PermissionMessage(pageCode = "tianquan-jianshen.permissions", key = "api.RoleActivation.replace", defaultLocale = "zh-CN",
        defaults = @LocalizedText(locale = "zh-CN", text = "原子替换当前会话激活角色集合"))
@PermissionMessage(pageCode = "tianquan-jianshen.permissions", key = "api.Runtime.gatewayDdcStatus", defaultLocale = "zh-CN",
        defaults = @LocalizedText(locale = "zh-CN", text = "分别查询 Definition、Tianshu Lease 和 Gateway Release"))
@PermissionMessage(pageCode = "tianquan-jianshen.permissions", key = "api.Runtime.mutations", defaultLocale = "zh-CN",
        defaults = @LocalizedText(locale = "zh-CN", text = "游标查询授权 Mutation Journal"))
@PermissionMessage(pageCode = "tianquan-jianshen.permissions", key = "api.Runtime.retry", defaultLocale = "zh-CN",
        defaults = @LocalizedText(locale = "zh-CN", text = "按 Mutation ID 触发幂等受控恢复"))
@PermissionMessage(pageCode = "tianquan-jianshen.permissions", key = "api.Runtime.status", defaultLocale = "zh-CN",
        defaults = @LocalizedText(locale = "zh-CN", text = "查询授权运行状态"))
@PermissionMessage(pageCode = "tianquan-jianshen.permissions", key = "api.User.changeStatus", defaultLocale = "zh-CN",
        defaults = @LocalizedText(locale = "zh-CN", text = "变更RBAC用户成员状态"))
@PermissionMessage(pageCode = "tianquan-jianshen.permissions", key = "api.User.create", defaultLocale = "zh-CN",
        defaults = @LocalizedText(locale = "zh-CN", text = "创建RBAC用户成员"))
@PermissionMessage(pageCode = "tianquan-jianshen.permissions", key = "api.User.delete", defaultLocale = "zh-CN",
        defaults = @LocalizedText(locale = "zh-CN", text = "归档RBAC用户成员"))
@PermissionMessage(pageCode = "tianquan-jianshen.permissions", key = "api.User.update", defaultLocale = "zh-CN",
        defaults = @LocalizedText(locale = "zh-CN", text = "更新RBAC用户成员绑定"))
@PermissionMessage(pageCode = "tianquan-jianshen.permissions", key = "api.User.user", defaultLocale = "zh-CN",
        defaults = @LocalizedText(locale = "zh-CN", text = "查询RBAC用户成员"))
@PermissionMessage(pageCode = "tianquan-jianshen.permissions", key = "api.User.users", defaultLocale = "zh-CN",
        defaults = @LocalizedText(locale = "zh-CN", text = "分页查询租户用户"))
@PermissionMessage(pageCode = "tianquan-jianshen.permissions", key = "api.UserBusinessAccess.accesses", defaultLocale = "zh-CN",
        defaults = @LocalizedText(locale = "zh-CN", text = "查询用户业务域授权"))
@PermissionMessage(pageCode = "tianquan-jianshen.permissions", key = "api.UserBusinessAccess.applicationAccesses", defaultLocale = "zh-CN",
        defaults = @LocalizedText(locale = "zh-CN", text = "查询用户派生应用访问范围"))
@PermissionMessage(pageCode = "tianquan-jianshen.permissions", key = "api.UserBusinessAccess.replace", defaultLocale = "zh-CN",
        defaults = @LocalizedText(locale = "zh-CN", text = "替换用户人工业务域授权"))
@PermissionMessage(pageCode = "tianquan-jianshen.permissions", key = "api.UserDirectory.changeUserStatus", defaultLocale = "zh-CN",
        defaults = @LocalizedText(locale = "zh-CN", text = "按授权版本变更租户用户状态"))
@PermissionMessage(pageCode = "tianquan-jianshen.permissions", key = "api.UserDirectory.user", defaultLocale = "zh-CN",
        defaults = @LocalizedText(locale = "zh-CN", text = "读取租户用户详情"))
@PermissionMessage(pageCode = "tianquan-jianshen.permissions", key = "api.UserDirectory.users", defaultLocale = "zh-CN",
        defaults = @LocalizedText(locale = "zh-CN", text = "分页查询租户用户"))
@PermissionMessage(pageCode = "tianquan-jianshen.permissions", key = "api.UserOrganizationAssignment.assign", defaultLocale = "zh-CN",
        defaults = @LocalizedText(locale = "zh-CN", text = "新增用户组织任职"))
@PermissionMessage(pageCode = "tianquan-jianshen.permissions", key = "api.UserOrganizationAssignment.list", defaultLocale = "zh-CN",
        defaults = @LocalizedText(locale = "zh-CN", text = "查询用户组织任职"))
@PermissionMessage(pageCode = "tianquan-jianshen.permissions", key = "api.UserOrganizationAssignment.revoke", defaultLocale = "zh-CN",
        defaults = @LocalizedText(locale = "zh-CN", text = "撤销用户组织任职"))
@PermissionMessage(pageCode = "tianquan-jianshen.permissions", key = "api.UserPositionAssignment.assign", defaultLocale = "zh-CN",
        defaults = @LocalizedText(locale = "zh-CN", text = "新增用户岗位任职"))
@PermissionMessage(pageCode = "tianquan-jianshen.permissions", key = "api.UserPositionAssignment.list", defaultLocale = "zh-CN",
        defaults = @LocalizedText(locale = "zh-CN", text = "查询用户岗位任职"))
@PermissionMessage(pageCode = "tianquan-jianshen.permissions", key = "api.UserPositionAssignment.revoke", defaultLocale = "zh-CN",
        defaults = @LocalizedText(locale = "zh-CN", text = "撤销用户岗位任职"))
@PermissionMessage(pageCode = "tianquan-jianshen.permissions", key = "permission.about.read", defaultLocale = "zh-CN",
        defaults = @LocalizedText(locale = "zh-CN", text = "Read authorization module information"))
@PermissionMessage(pageCode = "tianquan-jianshen.permissions", key = "permission.application.manage", defaultLocale = "zh-CN",
        defaults = @LocalizedText(locale = "zh-CN", text = "Manage tenant applications"))
@PermissionMessage(pageCode = "tianquan-jianshen.permissions", key = "permission.application.read", defaultLocale = "zh-CN",
        defaults = @LocalizedText(locale = "zh-CN", text = "Read tenant applications"))
@PermissionMessage(pageCode = "tianquan-jianshen.permissions", key = "permission.audit.read", defaultLocale = "zh-CN",
        defaults = @LocalizedText(locale = "zh-CN", text = "Read audit records"))
@PermissionMessage(pageCode = "tianquan-jianshen.permissions", key = "permission.authorization-constraint.manage", defaultLocale = "zh-CN",
        defaults = @LocalizedText(locale = "zh-CN", text = "Manage authorization constraints"))
@PermissionMessage(pageCode = "tianquan-jianshen.permissions", key = "permission.authorization-constraint.read", defaultLocale = "zh-CN",
        defaults = @LocalizedText(locale = "zh-CN", text = "Read authorization constraints"))
@PermissionMessage(pageCode = "tianquan-jianshen.permissions", key = "permission.authorization-runtime.operate", defaultLocale = "zh-CN",
        defaults = @LocalizedText(locale = "zh-CN", text = "Operate authorization runtime"))
@PermissionMessage(pageCode = "tianquan-jianshen.permissions", key = "permission.authorization-runtime.read", defaultLocale = "zh-CN",
        defaults = @LocalizedText(locale = "zh-CN", text = "Read authorization runtime"))
@PermissionMessage(pageCode = "tianquan-jianshen.permissions", key = "permission.authorization-simulation.execute", defaultLocale = "zh-CN",
        defaults = @LocalizedText(locale = "zh-CN", text = "Execute authorization simulations"))
@PermissionMessage(pageCode = "tianquan-jianshen.permissions", key = "permission.business.read", defaultLocale = "zh-CN",
        defaults = @LocalizedText(locale = "zh-CN", text = "Read business catalogs"))
@PermissionMessage(pageCode = "tianquan-jianshen.permissions", key = "permission.data-rule.manage", defaultLocale = "zh-CN",
        defaults = @LocalizedText(locale = "zh-CN", text = "Manage typed data rules"))
@PermissionMessage(pageCode = "tianquan-jianshen.permissions", key = "permission.data-rule.read", defaultLocale = "zh-CN",
        defaults = @LocalizedText(locale = "zh-CN", text = "Read typed data rules"))
@PermissionMessage(pageCode = "tianquan-jianshen.permissions", key = "permission.directory-snapshot.read", defaultLocale = "zh-CN",
        defaults = @LocalizedText(locale = "zh-CN", text = "Read directory snapshots"))
@PermissionMessage(pageCode = "tianquan-jianshen.permissions", key = "permission.directory.read", defaultLocale = "zh-CN",
        defaults = @LocalizedText(locale = "zh-CN", text = "Read organization directories"))
@PermissionMessage(pageCode = "tianquan-jianshen.permissions", key = "permission.directory.sync", defaultLocale = "zh-CN",
        defaults = @LocalizedText(locale = "zh-CN", text = "Synchronize organization directories"))
@PermissionMessage(pageCode = "tianquan-jianshen.permissions", key = "permission.field-definition.read", defaultLocale = "zh-CN",
        defaults = @LocalizedText(locale = "zh-CN", text = "Read historical field definitions"))
@PermissionMessage(pageCode = "tianquan-jianshen.permissions", key = "permission.field-rule.read", defaultLocale = "zh-CN",
        defaults = @LocalizedText(locale = "zh-CN", text = "Read historical field rules"))
@PermissionMessage(pageCode = "tianquan-jianshen.permissions", key = "permission.management-policy.manage", defaultLocale = "zh-CN",
        defaults = @LocalizedText(locale = "zh-CN", text = "Manage delegated management policies"))
@PermissionMessage(pageCode = "tianquan-jianshen.permissions", key = "permission.management-policy.read", defaultLocale = "zh-CN",
        defaults = @LocalizedText(locale = "zh-CN", text = "Read delegated management policies"))
@PermissionMessage(pageCode = "tianquan-jianshen.permissions", key = "permission.operation-sod.manage", defaultLocale = "zh-CN",
        defaults = @LocalizedText(locale = "zh-CN", text = "Manage operation separation rules"))
@PermissionMessage(pageCode = "tianquan-jianshen.permissions", key = "permission.operation-sod.read", defaultLocale = "zh-CN",
        defaults = @LocalizedText(locale = "zh-CN", text = "Read operation separation rules"))
@PermissionMessage(pageCode = "tianquan-jianshen.permissions", key = "permission.organization.manage", defaultLocale = "zh-CN",
        defaults = @LocalizedText(locale = "zh-CN", text = "Manage organizations"))
@PermissionMessage(pageCode = "tianquan-jianshen.permissions", key = "permission.organization.read", defaultLocale = "zh-CN",
        defaults = @LocalizedText(locale = "zh-CN", text = "Read organizations"))
@PermissionMessage(pageCode = "tianquan-jianshen.permissions", key = "permission.platform.admin", defaultLocale = "zh-CN",
        defaults = @LocalizedText(locale = "zh-CN", text = "Admin platform"))
@PermissionMessage(pageCode = "tianquan-jianshen.permissions", key = "permission.position.manage", defaultLocale = "zh-CN",
        defaults = @LocalizedText(locale = "zh-CN", text = "Manage positions"))
@PermissionMessage(pageCode = "tianquan-jianshen.permissions", key = "permission.position.read", defaultLocale = "zh-CN",
        defaults = @LocalizedText(locale = "zh-CN", text = "Read positions"))
@PermissionMessage(pageCode = "tianquan-jianshen.permissions", key = "permission.resource.archive", defaultLocale = "zh-CN",
        defaults = @LocalizedText(locale = "zh-CN", text = "Archive historical resources"))
@PermissionMessage(pageCode = "tianquan-jianshen.permissions", key = "permission.resource.read", defaultLocale = "zh-CN",
        defaults = @LocalizedText(locale = "zh-CN", text = "Read historical resources"))
@PermissionMessage(pageCode = "tianquan-jianshen.permissions", key = "permission.role-activation.read", defaultLocale = "zh-CN",
        defaults = @LocalizedText(locale = "zh-CN", text = "Read active roles"))
@PermissionMessage(pageCode = "tianquan-jianshen.permissions", key = "permission.role-activation.use", defaultLocale = "zh-CN",
        defaults = @LocalizedText(locale = "zh-CN", text = "Change active roles"))
@PermissionMessage(pageCode = "tianquan-jianshen.permissions", key = "permission.role-assignment.manage", defaultLocale = "zh-CN",
        defaults = @LocalizedText(locale = "zh-CN", text = "Manage user role assignments"))
@PermissionMessage(pageCode = "tianquan-jianshen.permissions", key = "permission.role-assignment.read", defaultLocale = "zh-CN",
        defaults = @LocalizedText(locale = "zh-CN", text = "Read user role assignments"))
@PermissionMessage(pageCode = "tianquan-jianshen.permissions", key = "permission.role-inheritance.manage", defaultLocale = "zh-CN",
        defaults = @LocalizedText(locale = "zh-CN", text = "Manage role inheritance"))
@PermissionMessage(pageCode = "tianquan-jianshen.permissions", key = "permission.role.create", defaultLocale = "zh-CN",
        defaults = @LocalizedText(locale = "zh-CN", text = "Create roles"))
@PermissionMessage(pageCode = "tianquan-jianshen.permissions", key = "permission.role.read", defaultLocale = "zh-CN",
        defaults = @LocalizedText(locale = "zh-CN", text = "Read roles"))
@PermissionMessage(pageCode = "tianquan-jianshen.permissions", key = "permission.role.update", defaultLocale = "zh-CN",
        defaults = @LocalizedText(locale = "zh-CN", text = "Update roles"))
@PermissionMessage(pageCode = "tianquan-jianshen.permissions", key = "permission.user-application-access.read", defaultLocale = "zh-CN",
        defaults = @LocalizedText(locale = "zh-CN", text = "Read user application access"))
@PermissionMessage(pageCode = "tianquan-jianshen.permissions", key = "permission.user-business-access.manage", defaultLocale = "zh-CN",
        defaults = @LocalizedText(locale = "zh-CN", text = "Manage user business access"))
@PermissionMessage(pageCode = "tianquan-jianshen.permissions", key = "permission.user-business-access.read", defaultLocale = "zh-CN",
        defaults = @LocalizedText(locale = "zh-CN", text = "Read user business access"))
@PermissionMessage(pageCode = "tianquan-jianshen.permissions", key = "permission.user-organization.manage", defaultLocale = "zh-CN",
        defaults = @LocalizedText(locale = "zh-CN", text = "Manage user organization assignments"))
@PermissionMessage(pageCode = "tianquan-jianshen.permissions", key = "permission.user-organization.read", defaultLocale = "zh-CN",
        defaults = @LocalizedText(locale = "zh-CN", text = "Read user organization assignments"))
@PermissionMessage(pageCode = "tianquan-jianshen.permissions", key = "permission.user-position.manage", defaultLocale = "zh-CN",
        defaults = @LocalizedText(locale = "zh-CN", text = "Manage user position assignments"))
@PermissionMessage(pageCode = "tianquan-jianshen.permissions", key = "permission.user-position.read", defaultLocale = "zh-CN",
        defaults = @LocalizedText(locale = "zh-CN", text = "Read user position assignments"))
@PermissionMessage(pageCode = "tianquan-jianshen.permissions", key = "permission.user-status.manage", defaultLocale = "zh-CN",
        defaults = @LocalizedText(locale = "zh-CN", text = "Manage user status"))
@PermissionMessage(pageCode = "tianquan-jianshen.permissions", key = "permission.user.manage", defaultLocale = "zh-CN",
        defaults = @LocalizedText(locale = "zh-CN", text = "Manage users"))
@PermissionMessage(pageCode = "tianquan-jianshen.permissions", key = "permission.user.read", defaultLocale = "zh-CN",
        defaults = @LocalizedText(locale = "zh-CN", text = "Read users"))
public final class Rbac3PermissionDefinitions {
    private Rbac3PermissionDefinitions() { }
}
