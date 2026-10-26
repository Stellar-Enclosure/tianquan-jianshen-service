package top.egon.cola.platform.tianquan.jianshen.admin.bootstrap.domain.dto;

import top.egon.cola.platform.tianquan.jianshen.contract.permission.CanonicalJson;

import java.util.Map;

/** Explicit database identity; the credential value is never part of a command, digest or receipt. */
public record PermissionBootstrapConnectionDTO(String jdbcUrl, String databaseName, String databaseOid,
        String databaseOwner, String username, String passwordFile, Integer idMachineId, String schema) {
    public PermissionBootstrapConnectionDTO {
        if (jdbcUrl == null || !jdbcUrl.matches("jdbc:postgresql://[A-Za-z0-9.\\[\\]:-]+/[A-Za-z0-9_]+")
                || databaseName == null || !databaseName.matches("[A-Za-z0-9_]{1,63}") || !jdbcUrl.endsWith("/" + databaseName)
                || databaseOid == null || !databaseOid.matches("[1-9][0-9]{0,9}")
                || username == null || !username.matches("[A-Za-z_][A-Za-z0-9_-]{0,62}") || !username.equals(databaseOwner)
                || passwordFile == null || passwordFile.isBlank() || idMachineId == null || idMachineId < 0 || idMachineId > 1023
                || !"public".equals(schema)) throw new IllegalArgumentException("PERMISSION_BOOTSTRAP_CONNECTION_INVALID");
    }

    public String bindingDigest() {
        return CanonicalJson.digest(Map.of("jdbcUrl", jdbcUrl, "databaseName", databaseName, "databaseOid", databaseOid,
                "databaseOwner", databaseOwner, "username", username, "schema", schema));
    }
}
