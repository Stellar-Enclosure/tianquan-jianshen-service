package top.egon.cola.platform.tianquan.jianshen.admin.authorization.grant.business.domain.command;

import top.egon.cola.platform.tianquan.jianshen.contract.permission.annotation.PermissionResource;
import top.egon.cola.platform.tianquan.jianshen.contract.permission.annotation.PermissionGroup;
import top.egon.cola.platform.tianquan.jianshen.contract.permission.annotation.FieldPermissions;
import top.egon.cola.platform.tianquan.jianshen.contract.permission.ResourceType;
import top.egon.cola.platform.tianquan.jianshen.contract.permission.PermissionManifest;

import jakarta.validation.Valid;
import jakarta.validation.constraints.NotNull;
import jakarta.validation.constraints.NotBlank;
import jakarta.validation.constraints.PositiveOrZero;
import top.egon.cola.platform.tianquan.jianshen.admin.authorization.grant.business.domain.enums.UserBusinessAccessStatusEnum;

import java.time.Instant;
import java.util.List;
import java.util.Objects;
import java.util.UUID;

/** Replaces only the target user's MANUAL Business grants. */
public record ReplaceUserBusinessAccessesCommand(
        @PermissionResource(key = "tianquan-jianshen.field.authorization.grant.business.domain.command.ReplaceUserBusinessAccessesCommand.commandId", type = ResourceType.FIELD,
                labelPage = "tianquan-jianshen.permissions", labelKey = "field.commandId")
        @FieldPermissions(valueType = PermissionManifest.JsonFieldType.STRING,
                write = @PermissionGroup(codes = {"system:user-business-access:manage"}))
        String commandId,
        @PermissionResource(key = "tianquan-jianshen.field.authorization.grant.business.domain.command.ReplaceUserBusinessAccessesCommand.items", type = ResourceType.FIELD,
                labelPage = "tianquan-jianshen.permissions", labelKey = "field.items")
        @FieldPermissions(valueType = PermissionManifest.JsonFieldType.ARRAY,
                write = @PermissionGroup(codes = {"system:user-business-access:manage"}))
        @Valid List<Item> items) {

    public ReplaceUserBusinessAccessesCommand(List<Item> items) {
        this(UUID.randomUUID().toString(), items);
    }

    public ReplaceUserBusinessAccessesCommand {
        commandId = required(commandId, "commandId");
        items = List.copyOf(Objects.requireNonNull(items, "items"));
    }

    /** One desired MANUAL Business grant fact. */
    public record Item(
            @PermissionResource(key = "tianquan-jianshen.field.authorization.grant.business.domain.command.ReplaceUserBusinessAccessesCommand.Item.ddcBusinessId", type = ResourceType.FIELD,
                    labelPage = "tianquan-jianshen.permissions", labelKey = "field.ddcBusinessId")
            @FieldPermissions(valueType = PermissionManifest.JsonFieldType.STRING,
                    write = @PermissionGroup(codes = {"system:user-business-access:manage"}))
            @NotBlank String ddcBusinessId,
            @PermissionResource(key = "tianquan-jianshen.field.authorization.grant.business.domain.command.ReplaceUserBusinessAccessesCommand.Item.status", type = ResourceType.FIELD,
                    labelPage = "tianquan-jianshen.permissions", labelKey = "field.status")
            @FieldPermissions(valueType = PermissionManifest.JsonFieldType.STRING,
                    write = @PermissionGroup(codes = {"system:user-business-access:manage"}))
            @NotNull UserBusinessAccessStatusEnum status,
            @PermissionResource(key = "tianquan-jianshen.field.authorization.grant.business.domain.command.ReplaceUserBusinessAccessesCommand.Item.validFrom", type = ResourceType.FIELD,
                    labelPage = "tianquan-jianshen.permissions", labelKey = "field.validFrom")
            @FieldPermissions(valueType = PermissionManifest.JsonFieldType.STRING,
                    write = @PermissionGroup(codes = {"system:user-business-access:manage"}))
            @com.fasterxml.jackson.annotation.JsonFormat(shape = com.fasterxml.jackson.annotation.JsonFormat.Shape.STRING)
            @NotNull Instant validFrom,
            @PermissionResource(key = "tianquan-jianshen.field.authorization.grant.business.domain.command.ReplaceUserBusinessAccessesCommand.Item.validTo", type = ResourceType.FIELD,
                    labelPage = "tianquan-jianshen.permissions", labelKey = "field.validTo")
            @FieldPermissions(valueType = PermissionManifest.JsonFieldType.STRING,
                    write = @PermissionGroup(codes = {"system:user-business-access:manage"}))
            @com.fasterxml.jackson.annotation.JsonFormat(shape = com.fasterxml.jackson.annotation.JsonFormat.Shape.STRING)
            Instant validTo,
            @PermissionResource(key = "tianquan-jianshen.field.authorization.grant.business.domain.command.ReplaceUserBusinessAccessesCommand.Item.reason", type = ResourceType.FIELD,
                    labelPage = "tianquan-jianshen.permissions", labelKey = "field.reason")
            @FieldPermissions(valueType = PermissionManifest.JsonFieldType.STRING,
                    write = @PermissionGroup(codes = {"system:user-business-access:manage"}))
            String reason,
            @PermissionResource(key = "tianquan-jianshen.field.authorization.grant.business.domain.command.ReplaceUserBusinessAccessesCommand.Item.ticketNo", type = ResourceType.FIELD,
                    labelPage = "tianquan-jianshen.permissions", labelKey = "field.ticketNo")
            @FieldPermissions(valueType = PermissionManifest.JsonFieldType.STRING,
                    write = @PermissionGroup(codes = {"system:user-business-access:manage"}))
            String ticketNo,
            @PermissionResource(key = "tianquan-jianshen.field.authorization.grant.business.domain.command.ReplaceUserBusinessAccessesCommand.Item.expectedVersion", type = ResourceType.FIELD,
                    labelPage = "tianquan-jianshen.permissions", labelKey = "field.expectedVersion")
            @FieldPermissions(valueType = PermissionManifest.JsonFieldType.NUMBER,
                    write = @PermissionGroup(codes = {"system:user-business-access:manage"}))
            @PositiveOrZero long expectedVersion) {

        public Item {
            ddcBusinessId = required(ddcBusinessId, "ddcBusinessId");
            Objects.requireNonNull(status, "status");
            Objects.requireNonNull(validFrom, "validFrom");
            if (validTo != null && !validTo.isAfter(validFrom)) {
                throw new IllegalArgumentException("validTo must be after validFrom");
            }
        }
    }

    private static String required(String value, String fieldName) {
        if (value == null || value.isBlank()) {
            throw new IllegalArgumentException(fieldName + " is required");
        }
        return value.trim();
    }
}
