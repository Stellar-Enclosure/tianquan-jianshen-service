package top.egon.cola.platform.tianquan.jianshen.admin.iam.position.service;

import top.egon.cola.platform.tianquan.jianshen.contract.permission.annotation.PermissionResource;
import top.egon.cola.platform.tianquan.jianshen.contract.permission.annotation.PermissionGroup;
import top.egon.cola.platform.tianquan.jianshen.contract.permission.annotation.FieldPermissions;
import top.egon.cola.platform.tianquan.jianshen.contract.permission.ResourceType;
import top.egon.cola.platform.tianquan.jianshen.contract.permission.PermissionMode;
import top.egon.cola.platform.tianquan.jianshen.contract.permission.PermissionManifest;

import jakarta.persistence.EntityManager;
import jakarta.persistence.LockModeType;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;
import top.egon.cola.component.common.id.snowflake.SnowflakeIdGenerator;
import top.egon.cola.platform.tianquan.jianshen.admin.iam.organization.domain.enums.OrgUnitStatusEnum;
import top.egon.cola.platform.tianquan.jianshen.admin.iam.organization.domain.enums.UserDirectoryAssignmentStatusEnum;
import top.egon.cola.platform.tianquan.jianshen.admin.iam.organization.domain.po.OrgUnitPO;
import top.egon.cola.platform.tianquan.jianshen.admin.iam.position.domain.po.PositionPO;
import top.egon.cola.platform.tianquan.jianshen.admin.iam.position.domain.enums.PositionStatusEnum;
import top.egon.cola.platform.tianquan.jianshen.admin.iam.position.domain.po.UserPositionAssignmentPO;
import top.egon.cola.platform.tianquan.jianshen.admin.iam.user.domain.enums.UserStatusEnum;
import top.egon.cola.platform.tianquan.jianshen.admin.iam.user.domain.po.UserPO;
import top.egon.cola.platform.tianquan.jianshen.admin.shared.domain.DatabaseClock;
import top.egon.cola.platform.tianquan.jianshen.core.rule.Rbac3RuleViolation;

import java.time.Instant;
import java.util.List;
import java.util.Objects;

/** Manages explicit user-to-position memberships owned by RBAC. */
@Service
public class UserPositionAssignmentService {

    private final EntityManager entityManager;
    private final DatabaseClock databaseClock;

    public UserPositionAssignmentService(
            EntityManager entityManager,
            DatabaseClock databaseClock) {
        this.entityManager = Objects.requireNonNull(entityManager, "entityManager");
        this.databaseClock = Objects.requireNonNull(databaseClock, "databaseClock");
    }

    @Transactional(readOnly = true)
    public List<AssignmentView> list(Long tenantId, Long userId) {
        return entityManager.createQuery("""
                        select a from UserPositionAssignmentEntity a
                         where a.tenantId = :tenantId and a.userId = :userId
                         order by a.id
                        """, UserPositionAssignmentPO.class)
                .setParameter("tenantId", tenantId)
                .setParameter("userId", userId)
                .getResultList()
                .stream()
                .map(UserPositionAssignmentService::view)
                .toList();
    }

    @Transactional
    public AssignmentView assign(
            Long tenantId,
            Long userId,
            AssignCommand command,
            String actorId) {
        Objects.requireNonNull(command, "command");
        if (command.orgUnitId() == null || command.positionId() == null) {
            throw new IllegalArgumentException("orgUnitId and positionId are required");
        }
        Instant now = databaseClock.transactionNow();
        UserPO user = requireUser(tenantId, userId, true);
        PositionPO position = requirePosition(tenantId, command.positionId());
        if (!command.orgUnitId().equals(position.getOrgUnitId())) {
            throw new Rbac3RuleViolation("DIRECTORY_POSITION_ORG_MISMATCH");
        }
        requireOrganization(tenantId, command.orgUnitId());
        Instant validFrom = command.validFrom() == null ? now : command.validFrom();
        Long assignmentId = SnowflakeIdGenerator.nextLongId();
        UserPositionAssignmentPO assignment = new UserPositionAssignmentPO(
                assignmentId, tenantId, user.getId(), command.orgUnitId(),
                position.getId(), command.primaryAssignment(), validFrom,
                command.validTo(), "MANUAL", "MANUAL:" + assignmentId,
                command.reason(), command.ticketNo(), actorId, now);
        entityManager.persist(assignment);
        user.applyAuthorizationChange(true, actorId, now);
        return view(assignment);
    }

    @Transactional
    public void revoke(
            Long tenantId,
            Long userId,
            Long assignmentId,
            long expectedVersion,
            String actorId) {
        Instant now = databaseClock.transactionNow();
        UserPositionAssignmentPO assignment = entityManager.find(
                UserPositionAssignmentPO.class, assignmentId,
                LockModeType.PESSIMISTIC_WRITE);
        if (assignment == null
                || !tenantId.equals(assignment.getTenantId())
                || !userId.equals(assignment.getUserId())) {
            throw new Rbac3RuleViolation("RESOURCE_NOT_FOUND");
        }
        if (!"MANUAL".equals(assignment.getSourceType())) {
            throw new IllegalStateException("directory snapshot assignment is read-only");
        }
        if (assignment.getVersion() != expectedVersion) {
            throw new Rbac3RuleViolation("DIRECTORY_VERSION_CONFLICT");
        }
        if (assignment.getStatus() != UserDirectoryAssignmentStatusEnum.ACTIVE
                && assignment.getStatus() != UserDirectoryAssignmentStatusEnum.SUSPENDED) {
            throw new IllegalStateException("position assignment is not revocable");
        }
        UserPO user = requireUser(tenantId, userId, false);
        assignment.revoke(actorId, now);
        user.applyAuthorizationChange(true, actorId, now);
    }

    private UserPO requireUser(Long tenantId, Long userId, boolean active) {
        UserPO user = entityManager.find(UserPO.class, userId, LockModeType.PESSIMISTIC_WRITE);
        if (user == null || !tenantId.equals(user.getTenantId())) {
            throw new Rbac3RuleViolation("USER_NOT_FOUND");
        }
        if (active && user.getStatus() != UserStatusEnum.ACTIVE) {
            throw new Rbac3RuleViolation("USER_INACTIVE");
        }
        return user;
    }

    private PositionPO requirePosition(Long tenantId, Long positionId) {
        PositionPO position = entityManager.find(PositionPO.class, positionId);
        if (position == null || !tenantId.equals(position.getTenantId())) {
            throw new Rbac3RuleViolation("DIRECTORY_POSITION_NOT_FOUND");
        }
        if (position.getStatus() != PositionStatusEnum.ACTIVE) {
            throw new Rbac3RuleViolation("DIRECTORY_POSITION_INACTIVE");
        }
        return position;
    }

    private void requireOrganization(Long tenantId, Long orgUnitId) {
        OrgUnitPO organization = entityManager.find(OrgUnitPO.class, orgUnitId);
        if (organization == null || !tenantId.equals(organization.getTenantId())) {
            throw new Rbac3RuleViolation("DIRECTORY_ORG_NOT_FOUND");
        }
        if (organization.getStatus() != OrgUnitStatusEnum.ACTIVE) {
            throw new Rbac3RuleViolation("DIRECTORY_ORG_INACTIVE");
        }
    }

    private static AssignmentView view(UserPositionAssignmentPO assignment) {
        return new AssignmentView(
                assignment.getId().toString(), assignment.getUserId().toString(),
                assignment.getOrgUnitId().toString(), assignment.getPositionId().toString(),
                assignment.isPrimaryAssignment(), assignment.getStatus().name(),
                assignment.getValidFrom(), assignment.getValidTo(),
                assignment.getSourceType(), assignment.getSourceId(),
                assignment.getReason(), assignment.getTicketNo(), assignment.getVersion());
    }

    public record AssignCommand(
            @PermissionResource(key = "tianquan-jianshen.field.iam.position.service.UserPositionAssignmentService.AssignCommand.orgUnitId", type = ResourceType.FIELD,
                    labelPage = "tianquan-jianshen.permissions", labelKey = "field.orgUnitId")
            @FieldPermissions(valueType = PermissionManifest.JsonFieldType.NUMBER,
                    write = @PermissionGroup(codes = {"system:user-position:manage"}))
            Long orgUnitId,
            @PermissionResource(key = "tianquan-jianshen.field.iam.position.service.UserPositionAssignmentService.AssignCommand.positionId", type = ResourceType.FIELD,
                    labelPage = "tianquan-jianshen.permissions", labelKey = "field.positionId")
            @FieldPermissions(valueType = PermissionManifest.JsonFieldType.NUMBER,
                    write = @PermissionGroup(codes = {"system:user-position:manage"}))
            Long positionId,
            @PermissionResource(key = "tianquan-jianshen.field.iam.position.service.UserPositionAssignmentService.AssignCommand.primaryAssignment", type = ResourceType.FIELD,
                    labelPage = "tianquan-jianshen.permissions", labelKey = "field.primaryAssignment")
            @FieldPermissions(valueType = PermissionManifest.JsonFieldType.BOOLEAN,
                    write = @PermissionGroup(codes = {"system:user-position:manage"}))
            boolean primaryAssignment,
            @PermissionResource(key = "tianquan-jianshen.field.iam.position.service.UserPositionAssignmentService.AssignCommand.validFrom", type = ResourceType.FIELD,
                    labelPage = "tianquan-jianshen.permissions", labelKey = "field.validFrom")
            @FieldPermissions(valueType = PermissionManifest.JsonFieldType.STRING,
                    write = @PermissionGroup(codes = {"system:user-position:manage"}))
            @com.fasterxml.jackson.annotation.JsonFormat(shape = com.fasterxml.jackson.annotation.JsonFormat.Shape.STRING)
            Instant validFrom,
            @PermissionResource(key = "tianquan-jianshen.field.iam.position.service.UserPositionAssignmentService.AssignCommand.validTo", type = ResourceType.FIELD,
                    labelPage = "tianquan-jianshen.permissions", labelKey = "field.validTo")
            @FieldPermissions(valueType = PermissionManifest.JsonFieldType.STRING,
                    write = @PermissionGroup(codes = {"system:user-position:manage"}))
            @com.fasterxml.jackson.annotation.JsonFormat(shape = com.fasterxml.jackson.annotation.JsonFormat.Shape.STRING)
            Instant validTo,
            @PermissionResource(key = "tianquan-jianshen.field.iam.position.service.UserPositionAssignmentService.AssignCommand.reason", type = ResourceType.FIELD,
                    labelPage = "tianquan-jianshen.permissions", labelKey = "field.reason")
            @FieldPermissions(valueType = PermissionManifest.JsonFieldType.STRING,
                    write = @PermissionGroup(codes = {"system:user-position:manage"}))
            String reason,
            @PermissionResource(key = "tianquan-jianshen.field.iam.position.service.UserPositionAssignmentService.AssignCommand.ticketNo", type = ResourceType.FIELD,
                    labelPage = "tianquan-jianshen.permissions", labelKey = "field.ticketNo")
            @FieldPermissions(valueType = PermissionManifest.JsonFieldType.STRING,
                    write = @PermissionGroup(codes = {"system:user-position:manage"}))
            String ticketNo) {
    }

    public record AssignmentView(
            @PermissionResource(key = "tianquan-jianshen.field.iam.position.service.UserPositionAssignmentService.AssignmentView.assignmentId", type = ResourceType.FIELD,
                    labelPage = "tianquan-jianshen.permissions", labelKey = "field.assignmentId")
            @FieldPermissions(valueType = PermissionManifest.JsonFieldType.STRING,
                    plainRead = @PermissionGroup(mode = PermissionMode.ANY, codes = {"system:user-position:manage", "system:user-position:read"}))
            String assignmentId,
            @PermissionResource(key = "tianquan-jianshen.field.iam.position.service.UserPositionAssignmentService.AssignmentView.userId", type = ResourceType.FIELD,
                    labelPage = "tianquan-jianshen.permissions", labelKey = "field.userId")
            @FieldPermissions(valueType = PermissionManifest.JsonFieldType.STRING,
                    plainRead = @PermissionGroup(mode = PermissionMode.ANY, codes = {"system:user-position:manage", "system:user-position:read"}))
            String userId,
            @PermissionResource(key = "tianquan-jianshen.field.iam.position.service.UserPositionAssignmentService.AssignmentView.orgUnitId", type = ResourceType.FIELD,
                    labelPage = "tianquan-jianshen.permissions", labelKey = "field.orgUnitId")
            @FieldPermissions(valueType = PermissionManifest.JsonFieldType.STRING,
                    plainRead = @PermissionGroup(mode = PermissionMode.ANY, codes = {"system:user-position:manage", "system:user-position:read"}))
            String orgUnitId,
            @PermissionResource(key = "tianquan-jianshen.field.iam.position.service.UserPositionAssignmentService.AssignmentView.positionId", type = ResourceType.FIELD,
                    labelPage = "tianquan-jianshen.permissions", labelKey = "field.positionId")
            @FieldPermissions(valueType = PermissionManifest.JsonFieldType.STRING,
                    plainRead = @PermissionGroup(mode = PermissionMode.ANY, codes = {"system:user-position:manage", "system:user-position:read"}))
            String positionId,
            @PermissionResource(key = "tianquan-jianshen.field.iam.position.service.UserPositionAssignmentService.AssignmentView.primaryAssignment", type = ResourceType.FIELD,
                    labelPage = "tianquan-jianshen.permissions", labelKey = "field.primaryAssignment")
            @FieldPermissions(valueType = PermissionManifest.JsonFieldType.BOOLEAN,
                    plainRead = @PermissionGroup(mode = PermissionMode.ANY, codes = {"system:user-position:manage", "system:user-position:read"}))
            boolean primaryAssignment,
            @PermissionResource(key = "tianquan-jianshen.field.iam.position.service.UserPositionAssignmentService.AssignmentView.status", type = ResourceType.FIELD,
                    labelPage = "tianquan-jianshen.permissions", labelKey = "field.status")
            @FieldPermissions(valueType = PermissionManifest.JsonFieldType.STRING,
                    plainRead = @PermissionGroup(mode = PermissionMode.ANY, codes = {"system:user-position:manage", "system:user-position:read"}))
            String status,
            @PermissionResource(key = "tianquan-jianshen.field.iam.position.service.UserPositionAssignmentService.AssignmentView.validFrom", type = ResourceType.FIELD,
                    labelPage = "tianquan-jianshen.permissions", labelKey = "field.validFrom")
            @FieldPermissions(valueType = PermissionManifest.JsonFieldType.STRING,
                    plainRead = @PermissionGroup(mode = PermissionMode.ANY, codes = {"system:user-position:manage", "system:user-position:read"}))
            @com.fasterxml.jackson.annotation.JsonFormat(shape = com.fasterxml.jackson.annotation.JsonFormat.Shape.STRING)
            Instant validFrom,
            @PermissionResource(key = "tianquan-jianshen.field.iam.position.service.UserPositionAssignmentService.AssignmentView.validTo", type = ResourceType.FIELD,
                    labelPage = "tianquan-jianshen.permissions", labelKey = "field.validTo")
            @FieldPermissions(valueType = PermissionManifest.JsonFieldType.STRING,
                    plainRead = @PermissionGroup(mode = PermissionMode.ANY, codes = {"system:user-position:manage", "system:user-position:read"}))
            @com.fasterxml.jackson.annotation.JsonFormat(shape = com.fasterxml.jackson.annotation.JsonFormat.Shape.STRING)
            Instant validTo,
            @PermissionResource(key = "tianquan-jianshen.field.iam.position.service.UserPositionAssignmentService.AssignmentView.sourceType", type = ResourceType.FIELD,
                    labelPage = "tianquan-jianshen.permissions", labelKey = "field.sourceType")
            @FieldPermissions(valueType = PermissionManifest.JsonFieldType.STRING,
                    plainRead = @PermissionGroup(mode = PermissionMode.ANY, codes = {"system:user-position:manage", "system:user-position:read"}))
            String sourceType,
            @PermissionResource(key = "tianquan-jianshen.field.iam.position.service.UserPositionAssignmentService.AssignmentView.sourceId", type = ResourceType.FIELD,
                    labelPage = "tianquan-jianshen.permissions", labelKey = "field.sourceId")
            @FieldPermissions(valueType = PermissionManifest.JsonFieldType.STRING,
                    plainRead = @PermissionGroup(mode = PermissionMode.ANY, codes = {"system:user-position:manage", "system:user-position:read"}))
            String sourceId,
            @PermissionResource(key = "tianquan-jianshen.field.iam.position.service.UserPositionAssignmentService.AssignmentView.reason", type = ResourceType.FIELD,
                    labelPage = "tianquan-jianshen.permissions", labelKey = "field.reason")
            @FieldPermissions(valueType = PermissionManifest.JsonFieldType.STRING,
                    plainRead = @PermissionGroup(mode = PermissionMode.ANY, codes = {"system:user-position:manage", "system:user-position:read"}))
            String reason,
            @PermissionResource(key = "tianquan-jianshen.field.iam.position.service.UserPositionAssignmentService.AssignmentView.ticketNo", type = ResourceType.FIELD,
                    labelPage = "tianquan-jianshen.permissions", labelKey = "field.ticketNo")
            @FieldPermissions(valueType = PermissionManifest.JsonFieldType.STRING,
                    plainRead = @PermissionGroup(mode = PermissionMode.ANY, codes = {"system:user-position:manage", "system:user-position:read"}))
            String ticketNo,
            @PermissionResource(key = "tianquan-jianshen.field.iam.position.service.UserPositionAssignmentService.AssignmentView.version", type = ResourceType.FIELD,
                    labelPage = "tianquan-jianshen.permissions", labelKey = "field.version")
            @FieldPermissions(valueType = PermissionManifest.JsonFieldType.NUMBER,
                    plainRead = @PermissionGroup(mode = PermissionMode.ANY, codes = {"system:user-position:manage", "system:user-position:read"}))
            long version) {
    }
}
