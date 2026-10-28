package top.egon.cola.platform.tianquan.jianshen.admin.authorization.runtime.catalog;

import com.fasterxml.jackson.core.JsonParser;
import com.fasterxml.jackson.databind.DeserializationFeature;
import com.fasterxml.jackson.databind.MapperFeature;
import com.fasterxml.jackson.databind.ObjectMapper;
import jakarta.servlet.http.HttpServletRequest;
import java.io.IOException;
import java.util.Arrays;
import java.util.Collections;
import java.util.Map;
import java.util.Set;
import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.annotation.Qualifier;
import org.springframework.boot.autoconfigure.condition.ConditionalOnProperty;
import org.springframework.dao.DataAccessException;
import org.springframework.http.CacheControl;
import org.springframework.http.MediaType;
import org.springframework.http.ResponseEntity;
import org.springframework.security.core.annotation.AuthenticationPrincipal;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.web.bind.annotation.ExceptionHandler;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RestController;
import top.egon.cola.component.yuheng.openapi.annotation.EgonGatewayPolicy;
import top.egon.cola.platform.tianquan.jianshen.contract.authorization.ExecutionAuthorizationContract;
import top.egon.cola.platform.tianquan.jianshen.contract.permission.PermissionManifest;
import top.egon.cola.platform.tianquan.jianshen.contract.permission.ResourceType;
import top.egon.cola.platform.tianquan.jianshen.contract.permission.annotation.LocalizedText;
import top.egon.cola.platform.tianquan.jianshen.contract.permission.annotation.PermissionMessage;
import top.egon.cola.platform.tianquan.jianshen.contract.permission.annotation.PermissionResource;
import top.egon.cola.platform.tianquan.jianshen.core.rule.Rbac3RuleViolation;
import top.egon.cola.platform.tianquan.shoubing.contract.ServiceIdentityPrincipal;
import top.egon.cola.platform.tianquan.shoubing.starter.security.IdpAuthenticationToken;
import top.egon.cola.platform.tianquan.shoubing.starter.security.RequiresServiceScope;

/** Sensitive sealed tickets are read only after SERVICE authentication and are never included in errors. */
@RestController
@ConditionalOnProperty(prefix = "egon.tianquan-jianshen.execution-grants", name = "enabled", havingValue = "true")
@PermissionMessage(pageCode = "permission.runtime", key = "executionGrant", defaultLocale = "en",
        defaults = @LocalizedText(locale = "en", text = "Evaluate a deferred execution intent"))
@Slf4j
public class ExecutionGrantAuthorizationController {
    private final ExecutionGrantAuthorizationService service;
    private final ObjectMapper mapper;

    public ExecutionGrantAuthorizationController(ExecutionGrantAuthorizationService service,
                                                  @Qualifier("jacksonObjectMapper") ObjectMapper mapper) {
        this.service = service;
        this.mapper = mapper.copy().enable(JsonParser.Feature.STRICT_DUPLICATE_DETECTION)
                .enable(DeserializationFeature.FAIL_ON_UNKNOWN_PROPERTIES, DeserializationFeature.FAIL_ON_TRAILING_TOKENS,
                        DeserializationFeature.FAIL_ON_MISSING_CREATOR_PROPERTIES, DeserializationFeature.FAIL_ON_NULL_CREATOR_PROPERTIES)
                .disable(MapperFeature.ALLOW_COERCION_OF_SCALARS);
    }

    @PostMapping(ExecutionAuthorizationContract.PATH)
    @PermissionResource(key = "tianquan-jianshen.api.runtime.executionGrant", type = ResourceType.API,
            labelPage = "permission.runtime", labelKey = "executionGrant", allowedPrincipals = PermissionManifest.PrincipalType.SERVICE,
            oauthScopes = ExecutionAuthorizationContract.SERVICE_SCOPE)
    @RequiresServiceScope(ExecutionAuthorizationContract.SERVICE_SCOPE)
    @EgonGatewayPolicy(exposure = EgonGatewayPolicy.Exposure.INTERNAL)
    public ResponseEntity<ExecutionAuthorizationContract.Decision> decide(HttpServletRequest request,
            @AuthenticationPrincipal ServiceIdentityPrincipal caller) throws IOException {
        var authentication = SecurityContextHolder.getContext().getAuthentication();
        if (!(authentication instanceof IdpAuthenticationToken verified) || !verified.isAuthenticated()
                || caller == null || verified.getPrincipal() != caller
                || !caller.scopes().contains(ExecutionAuthorizationContract.SERVICE_SCOPE)) {
            throw new Rbac3RuleViolation("SERVICE_IDENTITY_DENIED");
        }
        try {
            if (Collections.list(request.getHeaders("Content-Type")).size() != 1 || request.getContentType() == null
                    || !MediaType.APPLICATION_JSON.isCompatibleWith(MediaType.parseMediaType(request.getContentType()))) {
                throw new InvalidBody(415);
            }
        } catch (IllegalArgumentException invalid) { throw new InvalidBody(415); }
        byte[] bytes = request.getInputStream().readNBytes(ExecutionAuthorizationContract.MAX_REQUEST_BYTES + 1);
        try {
            if (bytes.length > ExecutionAuthorizationContract.MAX_REQUEST_BYTES) throw new InvalidBody(413);
            ExecutionAuthorizationContract.Request body;
            try {
                var node = mapper.readTree(bytes);
                if (node == null || !node.isObject() || node.size() != 3 || !node.path("systemCode").isTextual()
                        || !node.path("grantId").isTextual() || !node.path("ciphertext").isTextual()) throw new InvalidBody(400);
                body = mapper.treeToValue(node, ExecutionAuthorizationContract.Request.class);
            }
            catch (IOException | RuntimeException invalid) { throw new InvalidBody(400); }
            if (body == null) throw new InvalidBody(400);
            return ResponseEntity.ok().cacheControl(CacheControl.noStore()).body(service.decide(caller, verified.verifiedIssuer(), body));
        } finally { Arrays.fill(bytes, (byte) 0); }
    }

    @ExceptionHandler(Rbac3RuleViolation.class)
    public ResponseEntity<Map<String, String>> rejected(Rbac3RuleViolation failure) {
        if ("EXECUTION_GRANT_DENIED".equals(failure.reasonCode())) return error(403);
        if (Set.of("SERVICE_IDENTITY_DENIED", "APPLICATION_BINDING_DENIED").contains(failure.reasonCode())) {
            return ResponseEntity.status(403).cacheControl(CacheControl.noStore()).body(Map.of("error", "service_binding_denied"));
        }
        return error(503);
    }

    @ExceptionHandler(InvalidBody.class)
    public ResponseEntity<Map<String, String>> invalid(InvalidBody failure) { return error(failure.status); }

    @ExceptionHandler(org.springframework.security.access.AccessDeniedException.class)
    public ResponseEntity<Map<String, String>> denied() {
        return ResponseEntity.status(403).cacheControl(CacheControl.noStore()).body(Map.of("error", "insufficient_scope"));
    }

    @ExceptionHandler({DataAccessException.class, IOException.class,
            top.egon.cola.platform.tianquan.jianshen.starter.client.Rbac3AuthorizationClient.AuthorizationUnavailableException.class})
    public ResponseEntity<Map<String, String>> unavailable() { return error(503); }

    @ExceptionHandler(RuntimeException.class)
    public ResponseEntity<Map<String, String>> failed(RuntimeException failure) {
        log.error("Execution authorization request failed with {}", failure.getClass().getName());
        return error(500);
    }

    private static ResponseEntity<Map<String, String>> error(int status) {
        String code = switch (status) {
            case 400 -> "invalid_request";
            case 403 -> "access_denied";
            case 413 -> "request_too_large";
            case 415 -> "unsupported_media_type";
            case 503 -> "temporarily_unavailable";
            default -> "internal_error";
        };
        return ResponseEntity.status(status).cacheControl(CacheControl.noStore()).body(Map.of("error", code));
    }

    private static final class InvalidBody extends RuntimeException {
        private final int status;
        private InvalidBody(int status) { this.status = status; }
    }
}
