package top.egon.cola.platform.tianquan.jianshen.admin.authorization.policy.management.domain.vo;

import top.egon.cola.platform.tianquan.jianshen.contract.permission.annotation.PermissionResource;
import top.egon.cola.platform.tianquan.jianshen.contract.permission.ResourceAccess;
import top.egon.cola.platform.tianquan.jianshen.contract.permission.ResourceType;

/**
 * 可管理的租户成员标识；用户名及个人资料归 Tianquan-Shoubing 所有，不从 RBAC 用户表读取。
 * Manageable tenant membership identifiers; Tianquan-Shoubing owns usernames and profile data.
 *
 * @param userId RBAC 租户成员 ID；RBAC tenant membership ID.
 * @param identitySub Tianquan-Shoubing 身份标识；Tianquan-Shoubing subject identifier.
 */
public record ManagedUserVO(@PermissionResource(key = "tianquan-jianshen.field.authorization.policy.management.domain.vo.ManagedUserVO.userId", type = ResourceType.FIELD,
                labelPage = "tianquan-jianshen.permissions", labelKey = "field.userId", access = ResourceAccess.PUBLIC)
        String userId, @PermissionResource(key = "tianquan-jianshen.field.authorization.policy.management.domain.vo.ManagedUserVO.identitySub", type = ResourceType.FIELD,
                labelPage = "tianquan-jianshen.permissions", labelKey = "field.identitySub", access = ResourceAccess.PUBLIC)
        String identitySub) {
}
