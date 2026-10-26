package top.egon.cola.platform.tianquan.jianshen.admin.bootstrap.domain.dto;

import java.nio.file.Path;
import java.util.Objects;

/** A validated invocation contains exactly one owner operation and its private receipt destination. */
public record PermissionBootstrapInvocationDTO(PermissionCatalogBootstrapCommandDTO catalog,
        PermissionAdministratorBootstrapCommandDTO administrator, PermissionBootstrapConnectionDTO connection, Path receiptFile, boolean existingReceipt) {
    public PermissionBootstrapInvocationDTO {
        if ((catalog == null) == (administrator == null)) throw new IllegalArgumentException("exactly one bootstrap command required");
        Objects.requireNonNull(connection, "connection");
        Objects.requireNonNull(receiptFile, "receiptFile");
    }

    public String operationId() { return catalog == null ? administrator.operationId() : catalog.operationId(); }
    public Object command() { return catalog == null ? administrator : catalog; }
}
