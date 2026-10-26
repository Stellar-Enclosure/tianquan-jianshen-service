package top.egon.cola.platform.tianquan.jianshen.admin.bootstrap.domain.dto;

import top.egon.cola.platform.tianquan.jianshen.contract.permission.CatalogScope;

import java.time.Instant;
import java.util.List;
import java.util.Objects;

/** B1 is an explicit one-time administrative role for one activated catalog and one identity subject. */
public record PermissionAdministratorBootstrapCommandDTO(int schemaVersion, String operationId, String connectionFile, CatalogScope target,
        String expectedActiveRevision, String identitySub, String roleCode, String roleName, List<String> permissionCodes,
        Instant validFrom, Instant validTo, boolean activateRole) {
    public PermissionAdministratorBootstrapCommandDTO {
        PermissionCatalogBootstrapCommandDTO.requireVersion(schemaVersion);
        operationId = PermissionCatalogBootstrapCommandDTO.operation(operationId);
        connectionFile = PermissionCatalogBootstrapCommandDTO.text(connectionFile, "connectionFile", 4096);
        Objects.requireNonNull(target, "target");
        expectedActiveRevision = PermissionCatalogBootstrapCommandDTO.decimal(expectedActiveRevision);
        identitySub = PermissionCatalogBootstrapCommandDTO.text(identitySub, "identitySub", 200);
        roleCode = PermissionCatalogBootstrapCommandDTO.identifier(roleCode, "roleCode", 128);
        if (!roleCode.matches("[A-Z][A-Z0-9_]{2,63}")) throw new IllegalArgumentException("invalid bootstrap roleCode");
        roleName = PermissionCatalogBootstrapCommandDTO.text(roleName, "roleName", 200);
        permissionCodes = PermissionCatalogBootstrapCommandDTO.identifiers(permissionCodes, "permissionCodes", 256, true);
        if (validFrom != null && validTo != null && !validTo.isAfter(validFrom)) throw new IllegalArgumentException("invalid administrator grant interval");
    }
}
