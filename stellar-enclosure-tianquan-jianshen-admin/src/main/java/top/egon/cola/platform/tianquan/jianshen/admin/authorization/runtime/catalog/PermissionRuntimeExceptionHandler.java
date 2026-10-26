package top.egon.cola.platform.tianquan.jianshen.admin.authorization.runtime.catalog;

import org.springframework.core.Ordered;
import org.springframework.core.annotation.Order;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.ExceptionHandler;
import org.springframework.web.bind.annotation.RestControllerAdvice;
import top.egon.cola.component.common.core.pojo.ResultRecord;
import top.egon.cola.platform.tianquan.jianshen.core.rule.Rbac3RuleViolation;
import java.util.Set;

/** Runtime unavailability is distinct from an authorized empty permission set or a policy denial. */
@RestControllerAdvice(basePackages="top.egon.cola.platform.tianquan.jianshen.admin.authorization.runtime")
@Order(Ordered.HIGHEST_PRECEDENCE)
public class PermissionRuntimeExceptionHandler {
    @ExceptionHandler(Rbac3RuleViolation.class)
    public ResponseEntity<ResultRecord<Void>> rule(Rbac3RuleViolation failure) {
        String code=failure.reasonCode();
        int status=code.startsWith("AUTH_RUNTIME_") || code.startsWith("AUTH_SNAPSHOT_")
                || Set.of("AUTH_PROPAGATION_PENDING","AUTH_VERSION_MISMATCH","POLICY_VERSION_MISMATCH").contains(code) ? 503
                : code.startsWith("JWT_") || code.equals("IDENTITY_INACTIVE") ? 401 : 403;
        return ResponseEntity.status(status).header("Cache-Control","no-store")
                .body(ResultRecord.result(status,code,"Authorization request rejected",false,null));
    }
    @ExceptionHandler(org.springframework.dao.DataAccessException.class)
    public ResponseEntity<ResultRecord<Void>> databaseUnavailable(org.springframework.dao.DataAccessException failure) {
        return ResponseEntity.status(503).header("Cache-Control","no-store")
                .body(ResultRecord.result(503,"AUTH_RUNTIME_UNAVAILABLE","Authorization state is unavailable",false,null));
    }
}
