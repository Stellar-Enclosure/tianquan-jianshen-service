package top.egon.cola.platform.tianquan.jianshen.admin.authorization.policy.repository.jpa;

import jakarta.persistence.EntityManager;
import jakarta.persistence.LockModeType;
import top.egon.cola.platform.tianquan.jianshen.admin.registration.catalog.repository.CatalogAdministrationGuard;
import top.egon.cola.platform.tianquan.jianshen.admin.registration.catalog.repository.PermissionCatalogScopeRepository;
import top.egon.cola.platform.tianquan.jianshen.contract.permission.CatalogScope;
import top.egon.cola.platform.tianquan.jianshen.starter.security.Rbac3UserDetails;
import org.springframework.stereotype.Repository;
import org.springframework.transaction.annotation.Transactional;
import top.egon.cola.component.common.id.snowflake.SnowflakeIdGenerator;
import top.egon.cola.platform.tianquan.jianshen.admin.authorization.runtime.repository.AuthorizationEventPublisher;
import top.egon.cola.platform.tianquan.jianshen.admin.shared.domain.DatabaseClock;
import top.egon.cola.platform.tianquan.jianshen.admin.authorization.runtime.state.repository.TenantAuthorizationStateRepository;
import top.egon.cola.platform.tianquan.jianshen.admin.authorization.policy.domain.po.DataRulePO;
import top.egon.cola.platform.tianquan.jianshen.admin.authorization.policy.domain.po.DataRuleReferencePO;
import top.egon.cola.platform.tianquan.jianshen.admin.authorization.policy.domain.po.FieldRulePO;
import top.egon.cola.platform.tianquan.jianshen.admin.authorization.policy.domain.po.OperationSodRulePO;
import top.egon.cola.platform.tianquan.jianshen.admin.authorization.policy.domain.po.RoleCardinalityPO;
import top.egon.cola.platform.tianquan.jianshen.admin.authorization.policy.domain.po.RolePrerequisitePO;
import top.egon.cola.platform.tianquan.jianshen.admin.authorization.policy.domain.po.SodMemberPO;
import top.egon.cola.platform.tianquan.jianshen.admin.authorization.policy.domain.po.SodSetPO;
import top.egon.cola.platform.tianquan.jianshen.admin.iam.role.domain.po.RolePO;
import top.egon.cola.platform.tianquan.jianshen.core.rule.Rbac3RuleViolation;

import java.time.Instant;
import java.util.List;
import java.util.Map;
import top.egon.cola.platform.tianquan.jianshen.admin.authorization.policy.repository.RoleFactRepository;
import top.egon.cola.platform.tianquan.jianshen.admin.authorization.policy.repository.ConstraintRepository;
import top.egon.cola.platform.tianquan.jianshen.admin.authorization.policy.domain.vo.RoleFactVO;
import top.egon.cola.platform.tianquan.jianshen.admin.authorization.policy.domain.dto.SaveSodCommandDTO;
import top.egon.cola.platform.tianquan.jianshen.admin.authorization.policy.domain.dto.PrerequisiteGroupCommandDTO;
import top.egon.cola.platform.tianquan.jianshen.admin.authorization.policy.domain.dto.CardinalityCommandDTO;
import top.egon.cola.platform.tianquan.jianshen.admin.authorization.policy.domain.dto.DataRuleCommandDTO;
import top.egon.cola.platform.tianquan.jianshen.admin.authorization.policy.domain.dto.OperationSodRuleCommandDTO;
import top.egon.cola.platform.tianquan.jianshen.admin.authorization.policy.domain.vo.RuleReferenceVO;
import top.egon.cola.platform.tianquan.jianshen.admin.authorization.policy.domain.vo.MutationResultVO;
import top.egon.cola.platform.tianquan.jianshen.admin.authorization.policy.domain.vo.SodVO;
import top.egon.cola.platform.tianquan.jianshen.admin.authorization.policy.domain.vo.DataRuleVO;
import top.egon.cola.platform.tianquan.jianshen.admin.authorization.policy.domain.vo.FieldRuleVO;
import top.egon.cola.platform.tianquan.jianshen.admin.authorization.policy.domain.vo.OperationSodRuleVO;
import top.egon.cola.platform.tianquan.jianshen.admin.authorization.policy.domain.enums.DataRuleScopeTypeEnum;
import top.egon.cola.platform.tianquan.jianshen.admin.authorization.policy.domain.enums.DataRuleReferenceReferenceTypeEnum;
import top.egon.cola.platform.tianquan.jianshen.admin.authorization.policy.domain.enums.RoleCardinalityScopeTypeEnum;
import top.egon.cola.platform.tianquan.jianshen.admin.authorization.policy.domain.enums.RoleCardinalityStatusEnum;
import top.egon.cola.platform.tianquan.jianshen.admin.authorization.policy.domain.enums.RolePrerequisiteMatchModeEnum;
import top.egon.cola.platform.tianquan.jianshen.admin.authorization.policy.domain.enums.SodSetConstraintTypeEnum;
import top.egon.cola.platform.tianquan.jianshen.admin.authorization.runtime.domain.vo.AuthorizationEventVO;

/**
 * 类型 `JpaConstraintRepository` 位于当前包内，是类型，用于承载 `Constraint Repository` 相关的职责、状态或契约；调用方通常通过其公开 API、Spring 装配或实现关系使用。
 * Type `JpaConstraintRepository` is a type in its package and carries the responsibility, state, or contract for `Constraint Repository`; callers normally use it through its public API, Spring assembly, or implementation relationship.
 *
 * 语义与用法：将 `JpaConstraintRepository` 作为 `当前包` 的职责边界使用，优先依赖其已有构造、接口或 Spring 装配方式。
 * Semantics and usage: use `JpaConstraintRepository` as the responsibility boundary of `the current package`, following its existing construction, interface, or Spring-assembly mechanism.
 */
@Repository
public class JpaConstraintRepository implements
        ConstraintRepository,
        RoleFactRepository {

    /**
     * 字段 `entityManager` 表示 `JpaConstraintRepository` 中与 `entity Manager` 相关的状态、依赖、配置或结果（声明类型 `EntityManager`）；其生命周期和取值含义由声明类型及所属对象共同确定。
     * Field `entityManager` stores the `entity Manager`-related state, dependency, configuration, or result of `JpaConstraintRepository` (declared type `EntityManager`); its lifecycle and value semantics are defined by its declared type and owning object.
     *
     * 含义与用法：读取、传递或更新 `entityManager` 时应保持 `JpaConstraintRepository` 的生命周期、不可变性和线程安全约束。
     * Meaning and usage: when reading, passing, or updating `entityManager`, preserve `JpaConstraintRepository`'s lifecycle, immutability, and thread-safety constraints.
     */
    private final EntityManager entityManager;
    /**
     * 字段 `databaseClock` 表示 `JpaConstraintRepository` 中与 `database Clock` 相关的状态、依赖、配置或结果（声明类型 `DatabaseClock`）；其生命周期和取值含义由声明类型及所属对象共同确定。
     * Field `databaseClock` stores the `database Clock`-related state, dependency, configuration, or result of `JpaConstraintRepository` (declared type `DatabaseClock`); its lifecycle and value semantics are defined by its declared type and owning object.
     *
     * 含义与用法：读取、传递或更新 `databaseClock` 时应保持 `JpaConstraintRepository` 的生命周期、不可变性和线程安全约束。
     * Meaning and usage: when reading, passing, or updating `databaseClock`, preserve `JpaConstraintRepository`'s lifecycle, immutability, and thread-safety constraints.
     */
    private final DatabaseClock databaseClock;
    /**
     * 字段 `eventPort` 表示 `JpaConstraintRepository` 中与 `event Port` 相关的状态、依赖、配置或结果（声明类型 `AuthorizationEventPublisher`）；其生命周期和取值含义由声明类型及所属对象共同确定。
     * Field `eventPort` stores the `event Port`-related state, dependency, configuration, or result of `JpaConstraintRepository` (declared type `AuthorizationEventPublisher`); its lifecycle and value semantics are defined by its declared type and owning object.
     *
     * 含义与用法：读取、传递或更新 `eventPort` 时应保持 `JpaConstraintRepository` 的生命周期、不可变性和线程安全约束。
     * Meaning and usage: when reading, passing, or updating `eventPort`, preserve `JpaConstraintRepository`'s lifecycle, immutability, and thread-safety constraints.
     */
    private final AuthorizationEventPublisher eventPort;
    private final TenantAuthorizationStateRepository authorizationState;
    private final CatalogAdministrationGuard catalogGuard;

    /**
     * 构造器 `JpaConstraintRepository` 用于创建并初始化 `JpaConstraintRepository` 实例，建立该类型后续方法所依赖的状态和不变量。
     * Constructor `JpaConstraintRepository` creates and initializes `JpaConstraintRepository`, establishing the state and invariants required by subsequent operations.
     *
     * 用法：通过 `JpaConstraintRepository` 的构造入口创建实例，不绕过构造器建立的校验和初始化约束。
     * Usage: create the instance through `JpaConstraintRepository`'s constructor entry point and do not bypass the validation and initialization constraints established there.
     *
     * @param entityManager 输入参数 `entityManager`，用于确定本次操作的范围或内容；input value used to determine the operation's scope or content.
     * @param databaseClock 输入参数 `databaseClock`，用于确定本次操作的范围或内容；input value used to determine the operation's scope or content.
     * @param eventPort 输入参数 `eventPort`，用于确定本次操作的范围或内容；input value used to determine the operation's scope or content.
     * @param authorizationState 输入参数 `authorizationState`，用于确定本次操作的范围或内容；input value used to determine the operation's scope or content.
     */
    public JpaConstraintRepository(
            EntityManager entityManager,
            DatabaseClock databaseClock,
            AuthorizationEventPublisher eventPort,
            TenantAuthorizationStateRepository authorizationState,
            CatalogAdministrationGuard catalogGuard) {
        this.entityManager = entityManager;
        this.databaseClock = databaseClock;
        this.eventPort = eventPort;
        this.authorizationState = authorizationState;
        this.catalogGuard = catalogGuard;
    }

    /**
     * 方法 `require` 按照 `JpaConstraintRepository` 的职责处理输入，完成 `require` 操作并返回结果或产生声明的副作用；调用方应遵守参数和异常契约。
     * Method `require` processes its inputs according to `JpaConstraintRepository`'s responsibility, performs the `require` operation, and returns a result or declared side effect; callers must follow its parameter and exception contract.
     *
     * 用法：调用 `require` 前准备符合契约的参数，并根据返回值、异常或副作用继续业务流程。
     * Usage: provide contract-compliant arguments before calling `require`, then continue the business flow using its result, exception, or side effect.
     *
     * @param roleId 输入参数 `roleId`，用于确定本次操作的范围或内容；input value used to determine the operation's scope or content.
     * @return 操作产生的结果，其具体语义由返回类型和所属 API 定义；the result of the operation, whose exact semantics are defined by the return type and owning API.
     */
    @Override
    @Transactional(readOnly = true)
    public RoleFactVO require(String roleId) {
        RolePO role = entityManager.find(RolePO.class, Long.valueOf(roleId));
        if (role == null) {
            throw new Rbac3RuleViolation("RESOURCE_NOT_FOUND");
        }
        long parentCount = entityManager.createQuery("""
                        select count(i) from RoleInheritanceEntity i
                         where i.tenantId = :tenantId
                           and i.applicationId = :applicationId
                           and i.juniorRoleId = :roleId
                        """, Long.class)
                .setParameter("tenantId", role.getTenantId())
                .setParameter("applicationId", role.getApplicationId())
                .setParameter("roleId", role.getId())
                .getSingleResult();
        return new RoleFactVO(
                roleId, role.getApplicationId().toString(), parentCount == 0L);
    }

    /**
     * 方法 `sodSets` 按照 `JpaConstraintRepository` 的职责处理输入，完成 `sod Sets` 操作并返回结果或产生声明的副作用；调用方应遵守参数和异常契约。
     * Method `sodSets` processes its inputs according to `JpaConstraintRepository`'s responsibility, performs the `sod Sets` operation, and returns a result or declared side effect; callers must follow its parameter and exception contract.
     *
     * 用法：调用 `sodSets` 前准备符合契约的参数，并根据返回值、异常或副作用继续业务流程。
     * Usage: provide contract-compliant arguments before calling `sodSets`, then continue the business flow using its result, exception, or side effect.
     *
     * @param tenantId 输入参数 `tenantId`，用于确定本次操作的范围或内容；input value used to determine the operation's scope or content.
     * @return 操作产生的结果，其具体语义由返回类型和所属 API 定义；the result of the operation, whose exact semantics are defined by the return type and owning API.
     */
    @Override
    @Transactional(readOnly = true)
    public List<SodVO> sodSets(String tenantId) {
        return entityManager.createQuery("""
                        select s from SodSetEntity s
                         where s.tenantId = :tenantId order by s.setCode
                        """, SodSetPO.class)
                .setParameter("tenantId", Long.valueOf(tenantId))
                .getResultList().stream().map(this::toSodView).toList();
    }

    /**
     * 方法 `saveSod` 按照 `JpaConstraintRepository` 的职责处理输入，完成 `save Sod` 操作并返回结果或产生声明的副作用；调用方应遵守参数和异常契约。
     * Method `saveSod` processes its inputs according to `JpaConstraintRepository`'s responsibility, performs the `save Sod` operation, and returns a result or declared side effect; callers must follow its parameter and exception contract.
     *
     * 用法：调用 `saveSod` 前准备符合契约的参数，并根据返回值、异常或副作用继续业务流程。
     * Usage: provide contract-compliant arguments before calling `saveSod`, then continue the business flow using its result, exception, or side effect.
     *
     * @param command 输入参数 `command`，用于确定本次操作的范围或内容；input value used to determine the operation's scope or content.
     * @return 操作产生的结果，其具体语义由返回类型和所属 API 定义；the result of the operation, whose exact semantics are defined by the return type and owning API.
     */
    @Override
    @Transactional
    public MutationResultVO saveSod(
            SaveSodCommandDTO command) {
        Instant now = databaseClock.transactionNow();
        Long tenantId = Long.valueOf(command.tenantId());
        Long setId;
        if (command.setId() == null) {
            setId = SnowflakeIdGenerator.nextLongId();
            entityManager.persist(new SodSetPO(
                    setId,
                    tenantId,
                    value(command.applicationId()),
                    command.setCode(),
                    SodSetConstraintTypeEnum.valueOf(command.constraintType().name()),
                    command.maximumActiveRoles(),
                    command.validFrom(),
                    command.validTo(),
                    command.actorId(),
                    now));
        } else {
            setId = Long.valueOf(command.setId());
            SodSetPO set = entityManager.find(
                    SodSetPO.class, setId, LockModeType.PESSIMISTIC_WRITE);
            requireTenant(set, tenantId);
            requireVersion(set.getVersion(), command.expectedVersion());
            if (!set.getSetCode().equals(command.setCode())) {
                throw new Rbac3RuleViolation("REQUEST_INVALID");
            }
            set.update(
                    value(command.applicationId()),
                    SodSetConstraintTypeEnum.valueOf(command.constraintType().name()),
                    command.maximumActiveRoles(),
                    command.validFrom(),
                    command.validTo(),
                    command.actorId(),
                    now);
            entityManager.createQuery("""
                            delete from SodMemberEntity m
                             where m.tenantId = :tenantId and m.sodSetId = :setId
                            """)
                    .setParameter("tenantId", tenantId)
                    .setParameter("setId", setId)
                    .executeUpdate();
        }
        for (String roleId : command.roleIds()) {
            entityManager.persist(new SodMemberPO(tenantId, setId, Long.valueOf(roleId)));
        }
        return policyMutation(command.tenantId(), "SOD_SET", setId.toString(), command.actorId(), now);
    }

    /**
     * 方法 `savePrerequisites` 按照 `JpaConstraintRepository` 的职责处理输入，完成 `save Prerequisites` 操作并返回结果或产生声明的副作用；调用方应遵守参数和异常契约。
     * Method `savePrerequisites` processes its inputs according to `JpaConstraintRepository`'s responsibility, performs the `save Prerequisites` operation, and returns a result or declared side effect; callers must follow its parameter and exception contract.
     *
     * 用法：调用 `savePrerequisites` 前准备符合契约的参数，并根据返回值、异常或副作用继续业务流程。
     * Usage: provide contract-compliant arguments before calling `savePrerequisites`, then continue the business flow using its result, exception, or side effect.
     *
     * @param command 输入参数 `command`，用于确定本次操作的范围或内容；input value used to determine the operation's scope or content.
     * @return 操作产生的结果，其具体语义由返回类型和所属 API 定义；the result of the operation, whose exact semantics are defined by the return type and owning API.
     */
    @Override
    @Transactional
    public MutationResultVO savePrerequisites(
            PrerequisiteGroupCommandDTO command) {
        Instant now = databaseClock.transactionNow();
        Long tenantId = Long.valueOf(command.tenantId());
        RolePO target = entityManager.find(
                RolePO.class, Long.valueOf(command.targetRoleId()), LockModeType.PESSIMISTIC_WRITE);
        requireTenant(target, tenantId);
        requireVersion(target.getVersion(), command.expectedRoleVersion());
        entityManager.createQuery("""
                        delete from RolePrerequisiteEntity p
                         where p.tenantId = :tenantId
                           and p.targetRoleId = :targetRoleId
                           and p.groupCode = :groupCode
                        """)
                .setParameter("tenantId", tenantId)
                .setParameter("targetRoleId", target.getId())
                .setParameter("groupCode", command.groupCode())
                .executeUpdate();
        for (String roleId : command.prerequisiteRoleIds()) {
            entityManager.persist(new RolePrerequisitePO(
                    SnowflakeIdGenerator.nextLongId(),
                    tenantId,
                    target.getId(),
                    command.groupCode(),
                    RolePrerequisiteMatchModeEnum.valueOf(command.matchMode()),
                    Long.valueOf(roleId),
                    command.actorId(),
                    now));
        }
        target.markUpdated(command.actorId(), now);
        return policyMutation(
                command.tenantId(), "ROLE_PREREQUISITE", command.targetRoleId(),
                command.actorId(), now);
    }

    /**
     * 方法 `saveCardinality` 按照 `JpaConstraintRepository` 的职责处理输入，完成 `save Cardinality` 操作并返回结果或产生声明的副作用；调用方应遵守参数和异常契约。
     * Method `saveCardinality` processes its inputs according to `JpaConstraintRepository`'s responsibility, performs the `save Cardinality` operation, and returns a result or declared side effect; callers must follow its parameter and exception contract.
     *
     * 用法：调用 `saveCardinality` 前准备符合契约的参数，并根据返回值、异常或副作用继续业务流程。
     * Usage: provide contract-compliant arguments before calling `saveCardinality`, then continue the business flow using its result, exception, or side effect.
     *
     * @param command 输入参数 `command`，用于确定本次操作的范围或内容；input value used to determine the operation's scope or content.
     * @return 操作产生的结果，其具体语义由返回类型和所属 API 定义；the result of the operation, whose exact semantics are defined by the return type and owning API.
     */
    @Override
    @Transactional
    public MutationResultVO saveCardinality(
            CardinalityCommandDTO command) {
        Instant now = databaseClock.transactionNow();
        Long tenantId = Long.valueOf(command.tenantId());
        RolePO role = entityManager.find(
                RolePO.class, Long.valueOf(command.roleId()), LockModeType.PESSIMISTIC_WRITE);
        requireTenant(role, tenantId);
        List<RoleCardinalityPO> current = entityManager.createQuery("""
                        select c from RoleCardinalityEntity c
                         where c.tenantId = :tenantId and c.roleId = :roleId
                           and c.status = :status
                         order by c.validFrom desc
                        """, RoleCardinalityPO.class)
                .setParameter("tenantId", tenantId)
                .setParameter("roleId", role.getId())
                .setParameter("status", RoleCardinalityStatusEnum.ACTIVE)
                .setMaxResults(1)
                .setLockMode(LockModeType.PESSIMISTIC_WRITE)
                .getResultList();
        String resourceId;
        if (current.isEmpty()) {
            Long id = SnowflakeIdGenerator.nextLongId();
            entityManager.persist(new RoleCardinalityPO(
                    id, tenantId, role.getId(),
                    RoleCardinalityScopeTypeEnum.valueOf(command.scopeType()),
                    command.maximumActive(), command.validFrom(), command.validTo(),
                    command.actorId(), now));
            resourceId = id.toString();
        } else {
            RoleCardinalityPO cardinality = current.getFirst();
            requireVersion(cardinality.getVersion(), command.expectedVersion());
            cardinality.update(
                    RoleCardinalityScopeTypeEnum.valueOf(command.scopeType()),
                    command.maximumActive(), command.validFrom(), command.validTo(),
                    command.actorId(), now);
            resourceId = Long.toString(role.getId());
        }
        return policyMutation(
                command.tenantId(), "ROLE_CARDINALITY", resourceId, command.actorId(), now);
    }

    /**
     * 方法 `dataRules` 按照 `JpaConstraintRepository` 的职责处理输入，完成 `data Rules` 操作并返回结果或产生声明的副作用；调用方应遵守参数和异常契约。
     * Method `dataRules` processes its inputs according to `JpaConstraintRepository`'s responsibility, performs the `data Rules` operation, and returns a result or declared side effect; callers must follow its parameter and exception contract.
     *
     * 用法：调用 `dataRules` 前准备符合契约的参数，并根据返回值、异常或副作用继续业务流程。
     * Usage: provide contract-compliant arguments before calling `dataRules`, then continue the business flow using its result, exception, or side effect.
     *
     * @param target 已验证租户下的完整目录归属；complete catalog identity in the verified tenant.
     * @param actor 已认证 USER 身份；verified USER identity.
     * @return 操作产生的结果，其具体语义由返回类型和所属 API 定义；the result of the operation, whose exact semantics are defined by the return type and owning API.
     */
    @Override
    @Transactional
    public List<DataRuleVO> dataRules(CatalogScope target, Rbac3UserDetails actor) {
        if (target == null) throw new Rbac3RuleViolation("REQUEST_INVALID");
        var scope = catalogGuard.require(target, actor, "system:data-rule:read", databaseClock.transactionNow());
        return entityManager.createQuery("""
                        select r from DataRuleEntity r
                         where r.tenantId = :tenantId and r.catalogScopeId = :scopeId
                           and r.applicationId = :applicationId order by r.id
                        """, DataRulePO.class)
                .setParameter("tenantId", Long.parseLong(target.tenantId()))
                .setParameter("scopeId", Long.parseLong(target.catalogScopeId()))
                .setParameter("applicationId", scope.applicationId())
                .getResultList().stream().map(rule -> toDataRuleView(rule, target)).toList();
    }

    /**
     * 方法 `saveDataRule` 按照 `JpaConstraintRepository` 的职责处理输入，完成 `save Data Rule` 操作并返回结果或产生声明的副作用；调用方应遵守参数和异常契约。
     * Method `saveDataRule` processes its inputs according to `JpaConstraintRepository`'s responsibility, performs the `save Data Rule` operation, and returns a result or declared side effect; callers must follow its parameter and exception contract.
     *
     * 用法：调用 `saveDataRule` 前准备符合契约的参数，并根据返回值、异常或副作用继续业务流程。
     * Usage: provide contract-compliant arguments before calling `saveDataRule`, then continue the business flow using its result, exception, or side effect.
     *
     * @param command 输入参数 `command`，用于确定本次操作的范围或内容；input value used to determine the operation's scope or content.
     * @return 操作产生的结果，其具体语义由返回类型和所属 API 定义；the result of the operation, whose exact semantics are defined by the return type and owning API.
     */
    @Override
    @Transactional
    public MutationResultVO saveDataRule(
            DataRuleCommandDTO command) {
        Instant now = databaseClock.transactionNow();
        Long tenantId = Long.valueOf(command.tenantId());
        var scope = catalogGuard.require(command.target(), command.actor(), "system:data-rule:manage", now);
        verifyDataRuleCatalogFacts(scope, command);
        Long ruleId;
        if (command.ruleId() == null) {
            requireVersion(0, command.expectedVersion());
            ruleId = SnowflakeIdGenerator.nextLongId();
            entityManager.persist(new DataRulePO(
                    ruleId, tenantId, Long.parseLong(command.target().catalogScopeId()), Long.valueOf(command.applicationId()),
                    Long.valueOf(command.roleId()), Long.valueOf(command.permissionId()),
                    DataRuleScopeTypeEnum.valueOf(command.scopeType()),
                    command.directorySnapshotVersion(), command.validFrom(), command.validTo(),
                    command.actorId(), now));
        } else {
            ruleId = Long.valueOf(command.ruleId());
            DataRulePO rule = entityManager.find(
                    DataRulePO.class, ruleId, LockModeType.PESSIMISTIC_WRITE);
            requireTenant(rule, tenantId);
            if (!rule.getCatalogScopeId().equals(Long.parseLong(command.target().catalogScopeId()))
                    || !rule.getApplicationId().equals(scope.applicationId())
                    || !rule.getRoleId().equals(Long.parseLong(command.roleId()))
                    || !rule.getPermissionId().equals(Long.parseLong(command.permissionId()))) {
                throw new Rbac3RuleViolation("APPLICATION_BINDING_DENIED");
            }
            requireVersion(rule.getVersion(), command.expectedVersion());
            rule.update(
                    DataRuleScopeTypeEnum.valueOf(command.scopeType()),
                    command.directorySnapshotVersion(), command.validFrom(), command.validTo(),
                    command.actorId(), now);
            entityManager.createQuery("""
                            delete from DataRuleReferenceEntity r
                             where r.tenantId = :tenantId and r.dataRuleId = :ruleId
                            """)
                    .setParameter("tenantId", tenantId)
                    .setParameter("ruleId", ruleId)
                    .executeUpdate();
        }
        for (RuleReferenceVO reference : command.references()) {
            entityManager.persist(new DataRuleReferencePO(
                    tenantId,
                    ruleId,
                    DataRuleReferenceReferenceTypeEnum.valueOf(reference.referenceType()),
                    Long.valueOf(reference.referenceId())));
        }
        return policyMutation(command.tenantId(), "DATA_RULE", ruleId.toString(), command.actorId(), now);
    }

    /**
     * 方法 `fieldRules` 按照 `JpaConstraintRepository` 的职责处理输入，完成 `field Rules` 操作并返回结果或产生声明的副作用；调用方应遵守参数和异常契约。
     * Method `fieldRules` processes its inputs according to `JpaConstraintRepository`'s responsibility, performs the `field Rules` operation, and returns a result or declared side effect; callers must follow its parameter and exception contract.
     *
     * 用法：调用 `fieldRules` 前准备符合契约的参数，并根据返回值、异常或副作用继续业务流程。
     * Usage: provide contract-compliant arguments before calling `fieldRules`, then continue the business flow using its result, exception, or side effect.
     *
     * @param tenantId 输入参数 `tenantId`，用于确定本次操作的范围或内容；input value used to determine the operation's scope or content.
     * @return 操作产生的结果，其具体语义由返回类型和所属 API 定义；the result of the operation, whose exact semantics are defined by the return type and owning API.
     */
    @Override
    @Transactional(readOnly = true)
    public List<FieldRuleVO> fieldRules(String tenantId) {
        return entityManager.createQuery("""
                        select r from FieldRuleEntity r
                         where r.tenantId = :tenantId order by r.id
                        """, FieldRulePO.class)
                .setParameter("tenantId", Long.valueOf(tenantId))
                .getResultList().stream().map(rule -> new FieldRuleVO(
                        rule.getId().toString(), rule.getApplicationId().toString(),
                        rule.getRoleId().toString(), rule.getPermissionId().toString(),
                        rule.getFieldDefinitionId().toString(), rule.getAccessLevel().name(),
                        rule.getStatus().name(), rule.getVersion())).toList();
    }

    /**
     * 方法 `operationSodRules` 按照 `JpaConstraintRepository` 的职责处理输入，完成 `operation Sod Rules` 操作并返回结果或产生声明的副作用；调用方应遵守参数和异常契约。
     * Method `operationSodRules` processes its inputs according to `JpaConstraintRepository`'s responsibility, performs the `operation Sod Rules` operation, and returns a result or declared side effect; callers must follow its parameter and exception contract.
     *
     * 用法：调用 `operationSodRules` 前准备符合契约的参数，并根据返回值、异常或副作用继续业务流程。
     * Usage: provide contract-compliant arguments before calling `operationSodRules`, then continue the business flow using its result, exception, or side effect.
     *
     * @param tenantId 输入参数 `tenantId`，用于确定本次操作的范围或内容；input value used to determine the operation's scope or content.
     * @return 操作产生的结果，其具体语义由返回类型和所属 API 定义；the result of the operation, whose exact semantics are defined by the return type and owning API.
     */
    @Override
    @Transactional(readOnly = true)
    public List<OperationSodRuleVO> operationSodRules(String tenantId) {
        return entityManager.createQuery("""
                        select r from OperationSodRuleEntity r
                         where r.tenantId = :tenantId order by r.id
                        """, OperationSodRulePO.class)
                .setParameter("tenantId", Long.valueOf(tenantId))
                .getResultList().stream().map(rule ->
                        new OperationSodRuleVO(
                                rule.getId().toString(), rule.getApplicationCode(),
                                rule.getBusinessResource(), rule.getPriorActionCode(),
                                rule.getForbiddenLaterActionCode(), rule.getStatus().name(),
                                rule.getVersion())).toList();
    }

    /**
     * 方法 `saveOperationSodRule` 按照 `JpaConstraintRepository` 的职责处理输入，完成 `save Operation Sod Rule` 操作并返回结果或产生声明的副作用；调用方应遵守参数和异常契约。
     * Method `saveOperationSodRule` processes its inputs according to `JpaConstraintRepository`'s responsibility, performs the `save Operation Sod Rule` operation, and returns a result or declared side effect; callers must follow its parameter and exception contract.
     *
     * 用法：调用 `saveOperationSodRule` 前准备符合契约的参数，并根据返回值、异常或副作用继续业务流程。
     * Usage: provide contract-compliant arguments before calling `saveOperationSodRule`, then continue the business flow using its result, exception, or side effect.
     *
     * @param command 输入参数 `command`，用于确定本次操作的范围或内容；input value used to determine the operation's scope or content.
     * @return 操作产生的结果，其具体语义由返回类型和所属 API 定义；the result of the operation, whose exact semantics are defined by the return type and owning API.
     */
    @Override
    @Transactional
    public MutationResultVO saveOperationSodRule(
            OperationSodRuleCommandDTO command) {
        Instant now = databaseClock.transactionNow();
        Long tenantId = Long.valueOf(command.tenantId());
        Long ruleId;
        if (command.ruleId() == null) {
            ruleId = SnowflakeIdGenerator.nextLongId();
            entityManager.persist(new OperationSodRulePO(
                    ruleId, tenantId, command.applicationCode(), command.businessResource(),
                    command.priorActionCode(), command.forbiddenLaterActionCode(),
                    command.lookbackFrom(), command.validFrom(), command.validTo(),
                    command.actorId(), now));
        } else {
            ruleId = Long.valueOf(command.ruleId());
            OperationSodRulePO rule = entityManager.find(
                    OperationSodRulePO.class, ruleId, LockModeType.PESSIMISTIC_WRITE);
            requireTenant(rule, tenantId);
            requireVersion(rule.getVersion(), command.expectedVersion());
            if (!rule.getApplicationCode().equals(command.applicationCode())) {
                throw new Rbac3RuleViolation("ROLE_APPLICATION_MISMATCH");
            }
            rule.update(
                    command.businessResource(), command.priorActionCode(),
                    command.forbiddenLaterActionCode(), command.lookbackFrom(),
                    command.validFrom(), command.validTo(), command.actorId(), now);
        }
        return policyMutation(
                command.tenantId(), "OPERATION_SOD_RULE", ruleId.toString(),
                command.actorId(), now);
    }

    /**
     * 方法 `toSodView` 按照 `JpaConstraintRepository` 的职责处理输入，完成 `to Sod View` 操作并返回结果或产生声明的副作用；调用方应遵守参数和异常契约。
     * Method `toSodView` processes its inputs according to `JpaConstraintRepository`'s responsibility, performs the `to Sod View` operation, and returns a result or declared side effect; callers must follow its parameter and exception contract.
     *
     * 用法：调用 `toSodView` 前准备符合契约的参数，并根据返回值、异常或副作用继续业务流程。
     * Usage: provide contract-compliant arguments before calling `toSodView`, then continue the business flow using its result, exception, or side effect.
     *
     * @param set 输入参数 `set`，用于确定本次操作的范围或内容；input value used to determine the operation's scope or content.
     * @return 操作产生的结果，其具体语义由返回类型和所属 API 定义；the result of the operation, whose exact semantics are defined by the return type and owning API.
     */
    private SodVO toSodView(SodSetPO set) {
        List<String> roleIds = entityManager.createQuery("""
                        select m.roleId from SodMemberEntity m
                         where m.tenantId = :tenantId and m.sodSetId = :setId
                         order by m.roleId
                        """, Long.class)
                .setParameter("tenantId", set.getTenantId())
                .setParameter("setId", set.getId())
                .getResultList().stream().map(String::valueOf).toList();
        return new SodVO(
                set.getId().toString(), set.getSetCode(), set.getConstraintType().name(),
                string(set.getApplicationId()), set.getMaximumActiveRoles(), roleIds,
                set.getStatus().name(), set.getVersion());
    }

    /**
     * 方法 `toDataRuleView` 按照 `JpaConstraintRepository` 的职责处理输入，完成 `to Data Rule View` 操作并返回结果或产生声明的副作用；调用方应遵守参数和异常契约。
     * Method `toDataRuleView` processes its inputs according to `JpaConstraintRepository`'s responsibility, performs the `to Data Rule View` operation, and returns a result or declared side effect; callers must follow its parameter and exception contract.
     *
     * 用法：调用 `toDataRuleView` 前准备符合契约的参数，并根据返回值、异常或副作用继续业务流程。
     * Usage: provide contract-compliant arguments before calling `toDataRuleView`, then continue the business flow using its result, exception, or side effect.
     *
     * @param rule 输入参数 `rule`，用于确定本次操作的范围或内容；input value used to determine the operation's scope or content.
     * @return 操作产生的结果，其具体语义由返回类型和所属 API 定义；the result of the operation, whose exact semantics are defined by the return type and owning API.
     */
    private DataRuleVO toDataRuleView(DataRulePO rule, CatalogScope target) {
        List<RuleReferenceVO> references = entityManager.createQuery("""
                        select r from DataRuleReferenceEntity r
                         where r.tenantId = :tenantId and r.dataRuleId = :ruleId
                        """, DataRuleReferencePO.class)
                .setParameter("tenantId", rule.getTenantId())
                .setParameter("ruleId", rule.getId())
                .getResultList().stream().map(reference -> new RuleReferenceVO(
                        reference.getReferenceType().name(),
                        reference.getReferenceId().toString())).toList();
        return new DataRuleVO(
                target, rule.getId().toString(), rule.getApplicationId().toString(),
                rule.getRoleId().toString(), rule.getPermissionId().toString(),
                rule.getScopeType().name(), references, rule.getStatus().name(), rule.getVersion());
    }

    /** 校验目录角色与权限同属已锁定作用域。 / Verify role and permission ownership in the locked catalog scope. */
    private void verifyDataRuleCatalogFacts(PermissionCatalogScopeRepository.ScopeState scope, DataRuleCommandDTO command) {
        if (scope.applicationId() != Long.parseLong(command.applicationId())) {
            throw new Rbac3RuleViolation("APPLICATION_BINDING_DENIED");
        }
        List<?> facts = entityManager.createNativeQuery("""
                select r.id, p.id
                  from rbac3_catalog_role_binding b
                  join rbac3_role r on r.id=b.role_id and r.tenant_id=b.tenant_id and r.application_id=b.application_id
                  join rbac3_catalog_permission p on p.catalog_scope_id=b.catalog_scope_id
                 where b.catalog_scope_id=:scope and b.tenant_id=:tenant and b.application_id=:application
                   and b.role_id=:role and p.id=:permission and b.enabled and r.status='ACTIVE'
                   and p.governance_state='ACTIVE'
                 for share of b, r, p
                """)
                .setParameter("scope", Long.parseLong(command.target().catalogScopeId()))
                .setParameter("tenant", Long.parseLong(command.tenantId()))
                .setParameter("application", scope.applicationId())
                .setParameter("role", Long.parseLong(command.roleId()))
                .setParameter("permission", Long.parseLong(command.permissionId()))
                .getResultList();
        if (facts.size() != 1) throw new Rbac3RuleViolation("APPLICATION_BINDING_DENIED");
    }

    /**
     * 方法 `verifySameApplicationFacts` 按照 `JpaConstraintRepository` 的职责处理输入，完成 `verify Same Application Facts` 操作并返回结果或产生声明的副作用；调用方应遵守参数和异常契约。
     * Method `verifySameApplicationFacts` processes its inputs according to `JpaConstraintRepository`'s responsibility, performs the `verify Same Application Facts` operation, and returns a result or declared side effect; callers must follow its parameter and exception contract.
     *
     * 用法：调用 `verifySameApplicationFacts` 前准备符合契约的参数，并根据返回值、异常或副作用继续业务流程。
     * Usage: provide contract-compliant arguments before calling `verifySameApplicationFacts`, then continue the business flow using its result, exception, or side effect.
     *
     * @param tenantId 输入参数 `tenantId`，用于确定本次操作的范围或内容；input value used to determine the operation's scope or content.
     * @param applicationId 输入参数 `applicationId`，用于确定本次操作的范围或内容；input value used to determine the operation's scope or content.
     * @param roleId 输入参数 `roleId`，用于确定本次操作的范围或内容；input value used to determine the operation's scope or content.
     * @param permissionId 输入参数 `permissionId`，用于确定本次操作的范围或内容；input value used to determine the operation's scope or content.
     * @param fieldDefinitionId 输入参数 `fieldDefinitionId`，用于确定本次操作的范围或内容；input value used to determine the operation's scope or content.
     */
    private void verifySameApplicationFacts(
            String tenantId,
            String applicationId,
            String roleId,
            String permissionId,
            String fieldDefinitionId) {
        Long count = entityManager.createQuery("""
                        select count(r) from RoleEntity r, PermissionEntity p
                         where r.id = :roleId and p.id = :permissionId
                           and r.tenantId = :tenantId and p.tenantId = :tenantId
                           and r.applicationId = :applicationId
                           and p.applicationId = :applicationId
                        """, Long.class)
                .setParameter("roleId", Long.valueOf(roleId))
                .setParameter("permissionId", Long.valueOf(permissionId))
                .setParameter("tenantId", Long.valueOf(tenantId))
                .setParameter("applicationId", Long.valueOf(applicationId))
                .getSingleResult();
        if (count != 1L) {
            throw new Rbac3RuleViolation("ROLE_APPLICATION_MISMATCH");
        }
        if (fieldDefinitionId != null) {
            Long fieldCount = entityManager.createQuery("""
                            select count(f) from FieldDefinitionEntity f
                             where f.id = :fieldDefinitionId
                               and f.tenantId = :tenantId
                               and f.applicationId = :applicationId
                            """, Long.class)
                    .setParameter("fieldDefinitionId", Long.valueOf(fieldDefinitionId))
                    .setParameter("tenantId", Long.valueOf(tenantId))
                    .setParameter("applicationId", Long.valueOf(applicationId))
                    .getSingleResult();
            if (fieldCount != 1L) {
                throw new Rbac3RuleViolation("ROLE_APPLICATION_MISMATCH");
            }
        }
    }

    /**
     * 方法 `policyMutation` 按照 `JpaConstraintRepository` 的职责处理输入，完成 `policy Mutation` 操作并返回结果或产生声明的副作用；调用方应遵守参数和异常契约。
     * Method `policyMutation` processes its inputs according to `JpaConstraintRepository`'s responsibility, performs the `policy Mutation` operation, and returns a result or declared side effect; callers must follow its parameter and exception contract.
     *
     * 用法：调用 `policyMutation` 前准备符合契约的参数，并根据返回值、异常或副作用继续业务流程。
     * Usage: provide contract-compliant arguments before calling `policyMutation`, then continue the business flow using its result, exception, or side effect.
     *
     * @param tenantId 输入参数 `tenantId`，用于确定本次操作的范围或内容；input value used to determine the operation's scope or content.
     * @param aggregateType 输入参数 `aggregateType`，用于确定本次操作的范围或内容；input value used to determine the operation's scope or content.
     * @param aggregateId 输入参数 `aggregateId`，用于确定本次操作的范围或内容；input value used to determine the operation's scope or content.
     * @param actorId 输入参数 `actorId`，用于确定本次操作的范围或内容；input value used to determine the operation's scope or content.
     * @param now 输入参数 `now`，用于确定本次操作的范围或内容；input value used to determine the operation's scope or content.
     * @return 操作产生的结果，其具体语义由返回类型和所属 API 定义；the result of the operation, whose exact semantics are defined by the return type and owning API.
     */
    private MutationResultVO policyMutation(
            String tenantId,
            String aggregateType,
            String aggregateId,
            String actorId,
            Instant now) {
        long policyVersion;
        try {
            policyVersion = authorizationState.increment(Long.valueOf(tenantId), actorId);
        } catch (IllegalStateException missingState) {
            throw new Rbac3RuleViolation("RESOURCE_NOT_FOUND");
        }
        String eventType = aggregateType + "_CHANGED";
        String propagationId = eventPort.enqueue(new AuthorizationEventVO(
                tenantId,
                aggregateType,
                aggregateId,
                eventType,
                Map.of("policyVersion", Long.toString(policyVersion)),
                eventType.toLowerCase(java.util.Locale.ROOT) + '-' + aggregateId));
        return new MutationResultVO(
                aggregateId, policyVersion, propagationId, true);
    }

    /**
     * 方法 `requireTenant` 按照 `JpaConstraintRepository` 的职责处理输入，完成 `require Tenant` 操作并返回结果或产生声明的副作用；调用方应遵守参数和异常契约。
     * Method `requireTenant` processes its inputs according to `JpaConstraintRepository`'s responsibility, performs the `require Tenant` operation, and returns a result or declared side effect; callers must follow its parameter and exception contract.
     *
     * 用法：调用 `requireTenant` 前准备符合契约的参数，并根据返回值、异常或副作用继续业务流程。
     * Usage: provide contract-compliant arguments before calling `requireTenant`, then continue the business flow using its result, exception, or side effect.
     *
     * @param entity 输入参数 `entity`，用于确定本次操作的范围或内容；input value used to determine the operation's scope or content.
     * @param tenantId 输入参数 `tenantId`，用于确定本次操作的范围或内容；input value used to determine the operation's scope or content.
     */
    private static void requireTenant(Object entity, Long tenantId) {
        if (!(entity instanceof top.egon.cola.platform.tianquan.jianshen.admin.shared.domain.po.TenantScopedPO
                scoped) || !tenantId.equals(scoped.getTenantId())) {
            throw new Rbac3RuleViolation("RESOURCE_NOT_FOUND");
        }
    }

    /**
     * 方法 `requireVersion` 按照 `JpaConstraintRepository` 的职责处理输入，完成 `require Version` 操作并返回结果或产生声明的副作用；调用方应遵守参数和异常契约。
     * Method `requireVersion` processes its inputs according to `JpaConstraintRepository`'s responsibility, performs the `require Version` operation, and returns a result or declared side effect; callers must follow its parameter and exception contract.
     *
     * 用法：调用 `requireVersion` 前准备符合契约的参数，并根据返回值、异常或副作用继续业务流程。
     * Usage: provide contract-compliant arguments before calling `requireVersion`, then continue the business flow using its result, exception, or side effect.
     *
     * @param actual 输入参数 `actual`，用于确定本次操作的范围或内容；input value used to determine the operation's scope or content.
     * @param expected 输入参数 `expected`，用于确定本次操作的范围或内容；input value used to determine the operation's scope or content.
     */
    private static void requireVersion(long actual, long expected) {
        if (actual != expected) {
            throw new Rbac3RuleViolation("RESOURCE_VERSION_CONFLICT");
        }
    }

    /**
     * 方法 `value` 按照 `JpaConstraintRepository` 的职责处理输入，完成 `value` 操作并返回结果或产生声明的副作用；调用方应遵守参数和异常契约。
     * Method `value` processes its inputs according to `JpaConstraintRepository`'s responsibility, performs the `value` operation, and returns a result or declared side effect; callers must follow its parameter and exception contract.
     *
     * 用法：调用 `value` 前准备符合契约的参数，并根据返回值、异常或副作用继续业务流程。
     * Usage: provide contract-compliant arguments before calling `value`, then continue the business flow using its result, exception, or side effect.
     *
     * @param value 输入参数 `value`，用于确定本次操作的范围或内容；input value used to determine the operation's scope or content.
     * @return 操作产生的结果，其具体语义由返回类型和所属 API 定义；the result of the operation, whose exact semantics are defined by the return type and owning API.
     */
    private static Long value(String value) {
        return value == null ? null : Long.valueOf(value);
    }

    /**
     * 方法 `string` 按照 `JpaConstraintRepository` 的职责处理输入，完成 `string` 操作并返回结果或产生声明的副作用；调用方应遵守参数和异常契约。
     * Method `string` processes its inputs according to `JpaConstraintRepository`'s responsibility, performs the `string` operation, and returns a result or declared side effect; callers must follow its parameter and exception contract.
     *
     * 用法：调用 `string` 前准备符合契约的参数，并根据返回值、异常或副作用继续业务流程。
     * Usage: provide contract-compliant arguments before calling `string`, then continue the business flow using its result, exception, or side effect.
     *
     * @param value 输入参数 `value`，用于确定本次操作的范围或内容；input value used to determine the operation's scope or content.
     * @return 操作产生的结果，其具体语义由返回类型和所属 API 定义；the result of the operation, whose exact semantics are defined by the return type and owning API.
     */
    private static String string(Long value) {
        return value == null ? null : value.toString();
    }
}
