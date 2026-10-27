package top.egon.cola.platform.tianquan.jianshen.starter.authorization;

import jakarta.validation.Validator;
import java.util.function.Supplier;
import java.util.function.Function;
import java.util.concurrent.atomic.AtomicBoolean;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.web.context.request.RequestContextHolder;
import org.springframework.web.context.request.ServletRequestAttributes;
import top.egon.cola.component.common.core.validation.ValidationUtils;
import top.egon.cola.platform.tianquan.jianshen.contract.authorization.Decision;
import top.egon.cola.platform.tianquan.jianshen.starter.security.Rbac3ContextAuthentication;
import top.egon.cola.platform.tianquan.shoubing.contract.IdentityPrincipal;
import top.egon.cola.platform.tianquan.shoubing.core.observability.SecurityMetricObservationBO;
import top.egon.cola.platform.tianquan.shoubing.starter.security.IdpSecurityObservationFilter;
import top.egon.cola.platform.tianquan.shoubing.starter.security.domain.TokenAuditProofBO;
import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.annotation.Qualifier;
import top.egon.cola.platform.tianquan.jianshen.contract.authorization.AuthorizationDecision;
import top.egon.cola.platform.tianquan.jianshen.contract.authorization.AuthorizationFenceDecision;
import top.egon.cola.platform.tianquan.jianshen.contract.authorization.DataScopeDecision;
import top.egon.cola.platform.tianquan.jianshen.contract.authorization.FieldPolicyDecision;
import top.egon.cola.platform.tianquan.jianshen.contract.authorization.OperationSodDecision;
import top.egon.cola.platform.tianquan.jianshen.contract.authorization.PermissionRequest;
import top.egon.cola.platform.tianquan.shoubing.core.observability.IdpSecurityMetricsRecorder;
import top.egon.cola.platform.tianquan.shoubing.starter.security.IdpObservedVerificationComponent;
import top.egon.cola.platform.tianquan.shoubing.starter.security.rpc.IdpRpcSecurityContext;
import top.egon.cola.platform.tianquan.jianshen.starter.permission.PermissionDenialAudit;
import top.egon.cola.platform.tianquan.jianshen.starter.permission.PermissionPolicyRegistry;

/** Observes the original PDP once without changing its policy results or exception contract. */
@Slf4j
public class Rbac3ObservedAuthorizationService implements AuthorizationService {
    @Qualifier("rbac3AuthorizationDelegate") private final AuthorizationService delegate;
    @Qualifier("idpSecurityMetricsRecorder") private final IdpSecurityMetricsRecorder metrics;
    @Qualifier("idpObservedVerificationComponent") private final IdpObservedVerificationComponent observations;
    @Qualifier("defaultValidator") private final Validator validator;
    private final PermissionDenialAudit diagnostic;
    private final PermissionPolicyRegistry registry;

    private final AtomicBoolean metricFailureLogged = new AtomicBoolean();

    public Rbac3ObservedAuthorizationService(AuthorizationService delegate, IdpSecurityMetricsRecorder metrics,
            IdpObservedVerificationComponent observations, Validator validator) {
        this(delegate, metrics, observations, validator, null, null);
    }

    public Rbac3ObservedAuthorizationService(AuthorizationService delegate, IdpSecurityMetricsRecorder metrics,
            IdpObservedVerificationComponent observations, Validator validator,
            PermissionDenialAudit diagnostic, PermissionPolicyRegistry registry) {
        this.delegate = delegate; this.metrics = metrics; this.observations = observations; this.validator = validator;
        this.diagnostic = diagnostic; this.registry = registry;
    }

    @Override public AuthorizationDecision requirePermission(PermissionRequest request) {
        new ValidationUtils(validator).validate(request);
        return observe(() -> delegate.requirePermission(request), AuthorizationDecision::decision);
    }
    @Override public DataScopeDecision decideDataScope(DataScopeRequest request) {
        new ValidationUtils(validator).validate(request);
        if (diagnostic != null && registry != null && delegate instanceof DefaultAuthorizationService service) {
            var evaluation = new DefaultAuthorizationService.DataScopeEvaluation[1];
            return observe(() -> {
                evaluation[0] = service.evaluateDataScope(request);
                return evaluation[0].decision();
            }, DataScopeDecision::decision,
                    result -> diagnostic.observedDataScopeDenied(result, evaluation[0].snapshot(), registry));
        }
        return observe(() -> delegate.decideDataScope(request), DataScopeDecision::decision);
    }
    @Override public FieldPolicyDecision decideFields(FieldPolicyRequest request) {
        new ValidationUtils(validator).validate(request);
        return observe(() -> delegate.decideFields(request), FieldPolicyDecision::decision);
    }
    @Override public OperationSodDecision checkParticipation(OperationSodRequest request) {
        new ValidationUtils(validator).validate(request);
        return observe(() -> delegate.checkParticipation(request), OperationSodDecision::decision);
    }
    @Override public AuthorizationFenceDecision verifyFence(AuthorizationFenceRequest request) {
        new ValidationUtils(validator).validate(request);
        return observe(() -> delegate.verifyFence(request), AuthorizationFenceDecision::decision);
    }

    private <T> T observe(Supplier<T> original, Function<T, Decision> classify) {
        return observe(original, classify, ignored -> { });
    }

    private <T> T observe(Supplier<T> original, Function<T, Decision> classify, java.util.function.Consumer<T> confirmedDenial) {
        T result;
        try { result = original.get(); }
        catch (RuntimeException failure) {
            String category = failure instanceof RuntimeUnavailableException ? "INDETERMINATE"
                    : failure instanceof org.springframework.security.access.AccessDeniedException
                            || failure instanceof DefaultAuthorizationService.AuthorizationDeniedException ? "DENY" : "FAILURE";
            metric(category);
            if (!"FAILURE".equals(category)) { deniedHandoff(); }
            throw failure;
        }
        new ValidationUtils(validator).validate(result);
        Decision decision = classify.apply(result);
        metric(decision.name());
        if (decision != Decision.ALLOW) {
            boolean confirmed = deniedHandoff();
            if (decision == Decision.DENY && confirmed) {
                try { confirmedDenial.accept(result); }
                catch (RuntimeException failure) { log.warn("Data scope diagnostic unavailable failureType={}", failure.getClass().getSimpleName()); }
            }
        }
        return result;
    }

    private boolean deniedHandoff() {
        var authentication = SecurityContextHolder.getContext().getAuthentication();
        if (authentication == null || !(authentication.getDetails() instanceof TokenAuditProofBO proof)) { return false; }
        boolean confirmed;
        if (RequestContextHolder.getRequestAttributes() instanceof ServletRequestAttributes servlet) {
            var marker = IdpSecurityObservationFilter.authorizationObservationContext(servlet.getRequest());
            confirmed = marker != null && marker.denyOnce(() -> observations.authorizationDenied(proof));
        } else if (IdpRpcSecurityContext.currentProofOrNull() != null) {
            var marker = IdpRpcSecurityContext.currentAuthorizationObservationContext();
            confirmed = marker != null && marker.denyOnce(() -> observations.authorizationDenied(proof));
            if (marker != null && marker.isFailed()) { confirmed = false; }
        } else {
            confirmed = observations.authorizationDenied(proof);
        }
        if (!confirmed) {
            IdentityPrincipal identity = authentication instanceof Rbac3ContextAuthentication context
                    ? context.context().identity() : (IdentityPrincipal) authentication.getPrincipal();
            throw new RuntimeUnavailableException("OAUTH_AUDIT_DELIVERY_UNAVAILABLE", identity);
        }
        if (RequestContextHolder.getRequestAttributes() instanceof ServletRequestAttributes servlet) {
            IdpSecurityObservationFilter.authorizationDeniedRecorded(servlet.getRequest());
        }
        return true;
    }

    private void metric(String result) {
        try { metrics.record(SecurityMetricObservationBO.builder().signal("rbac.authorization").result(result).build()); }
        catch (RuntimeException failure) {
            if (metricFailureLogged.compareAndSet(false, true)) {
                log.warn("Authorization metric unavailable; failureType={}", failure.getClass().getSimpleName());
            }
        }
    }
}
