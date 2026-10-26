package top.egon.cola.platform.tianquan.jianshen.admin.registration.catalog.controller;

import jakarta.persistence.PersistenceException;
import jakarta.servlet.http.HttpServletRequest;
import org.springframework.core.Ordered;
import org.springframework.core.annotation.Order;
import org.springframework.dao.DataAccessException;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.ExceptionHandler;
import org.springframework.web.bind.annotation.RestControllerAdvice;
import top.egon.cola.component.common.core.pojo.ResultRecord;
import top.egon.cola.platform.tianquan.jianshen.contract.error.Rbac3ErrorCode;
import top.egon.cola.platform.tianquan.jianshen.core.rule.Rbac3RuleViolation;
import top.egon.cola.platform.tianquan.shoubing.starter.security.IdpSecurityObservationFilter;

import java.io.IOException;
import java.sql.SQLException;
import java.util.HashSet;
import java.util.Set;

/** Registry failures never expose SQL, token material or a partially written candidate. */
@RestControllerAdvice(basePackages = {
        "top.egon.cola.platform.tianquan.jianshen.admin.registration.catalog.controller",
        "top.egon.cola.platform.tianquan.jianshen.admin.authorization.catalog.controller",
        "top.egon.cola.platform.tianquan.jianshen.admin.authorization.grant.rolepermission.controller"
})
@Order(Ordered.HIGHEST_PRECEDENCE)
public class PermissionCatalogExceptionHandler {

    @ExceptionHandler(Rbac3RuleViolation.class)
    ResponseEntity<ResultRecord<Void>> rule(Rbac3RuleViolation failure, HttpServletRequest request) {
        Rbac3ErrorCode code = Rbac3ErrorCode.valueOf(failure.reasonCode());
        if (code.httpStatus() == 403 && !IdpSecurityObservationFilter.beforeAuthorizationDenied(request)) {
            return ResponseEntity.status(503).header("Cache-Control", "no-store").body(ResultRecord.result(503,
                    "OAUTH_AUDIT_DELIVERY_UNAVAILABLE", "Authorization audit authority is unavailable", false, null));
        }
        return ResponseEntity.status(code.httpStatus()).header("Cache-Control", "no-store")
                .body(ResultRecord.result(code.httpStatus(), code.name(), "Permission catalog request rejected", false, null));
    }

    @ExceptionHandler({IllegalArgumentException.class, IOException.class})
    ResponseEntity<ResultRecord<Void>> invalid(Exception failure) {
        return ResponseEntity.unprocessableEntity().body(ResultRecord.result(422, "RESOURCE_MANIFEST_INVALID",
                "Invalid permission catalog request", false, null));
    }

    @ExceptionHandler({DataAccessException.class, PersistenceException.class})
    ResponseEntity<ResultRecord<Void>> database(RuntimeException failure) {
        Set<Throwable> visited = new HashSet<>();
        for (Throwable cause = failure; cause != null && visited.add(cause); cause = cause.getCause()) {
            if (cause instanceof SQLException sql && sql.getSQLState() != null
                    && Set.of("23505", "23503", "23514", "55000", "40001", "40P01").contains(sql.getSQLState())) {
                return ResponseEntity.status(409).body(ResultRecord.result(409, "RESOURCE_MANIFEST_CONFLICT",
                        "Catalog state changed; inspect the operation and prepare a fresh plan", false, null));
            }
        }
        return ResponseEntity.status(503).body(ResultRecord.result(503, "AUTH_RUNTIME_UNAVAILABLE",
                "Catalog authority is unavailable; inspect the operation before retrying", false, null));
    }
}
