package top.egon.cola.platform.tianquan.jianshen.starter.security;

import org.aopalliance.intercept.MethodInvocation;
import org.springframework.security.authorization.AuthorizationDecision;
import org.springframework.security.authorization.AuthorizationManager;
import org.springframework.security.core.Authentication;
import org.springframework.beans.factory.annotation.Qualifier;
import jakarta.validation.Validator;
import lombok.AccessLevel;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import top.egon.cola.platform.tianquan.jianshen.starter.autoconfigure.Rbac3StarterProperties.UserScopePolicyProperties;
import top.egon.cola.platform.tianquan.shoubing.starter.security.IdpObservedVerificationComponent;
import top.egon.cola.platform.tianquan.shoubing.core.observability.IdpSecurityMetricsRecorder;
import top.egon.cola.platform.tianquan.shoubing.core.observability.SecurityMetricObservationBO;
import top.egon.cola.platform.tianquan.shoubing.contract.IdentityPrincipal;
import top.egon.cola.platform.tianquan.shoubing.contract.ServiceIdentityPrincipal;
import top.egon.cola.platform.tianquan.shoubing.starter.security.domain.TokenAuditProofBO;
import top.egon.cola.platform.tianquan.shoubing.starter.security.IdpSecurityObservationFilter;
import top.egon.cola.platform.tianquan.shoubing.starter.security.rpc.IdpRpcSecurityContext;
import top.egon.cola.component.common.core.validation.ValidationUtils;
import org.springframework.web.context.request.RequestContextHolder;
import org.springframework.web.context.request.ServletRequestAttributes;
import top.egon.cola.platform.tianquan.jianshen.contract.authorization.Decision;
import top.egon.cola.platform.tianquan.jianshen.contract.authorization.PermissionRequest;
import top.egon.cola.platform.tianquan.jianshen.starter.authorization.AuthorizationService;

import java.lang.reflect.AnnotatedElement;
import java.lang.reflect.Method;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Objects;
import java.util.Map;
import java.util.Set;
import java.util.concurrent.atomic.AtomicBoolean;
import java.util.function.Supplier;

/**
 * Spring Method Security PEP shared by API-resource and generic permission annotations.
 *
 * <p>All declared permissions are evaluated through the existing AuthorizationService. The
 * manager fails closed for denied or indeterminate decisions and never relies on URL rules.</p>
 */
@Slf4j
@RequiredArgsConstructor(access = AccessLevel.PRIVATE)
public final class Rbac3MethodAuthorizationManager
        implements AuthorizationManager<MethodInvocation> {

    @Qualifier("authorizationService") private final AuthorizationService authorization;
    private final boolean userScopesEnabled;
    private final Map<String, Set<String>> permissionScopes;
    @Qualifier("idpObservedVerificationComponent") private final IdpObservedVerificationComponent observations;
    @Qualifier("idpSecurityMetricsRecorder") private final IdpSecurityMetricsRecorder metrics;
    @Qualifier("defaultValidator") private final Validator validator;
    private final top.egon.cola.platform.tianquan.jianshen.starter.permission.PermissionExecutionGuard compiledPolicy;
    private final AtomicBoolean metricFailureLogged = new AtomicBoolean();

    public Rbac3MethodAuthorizationManager(AuthorizationService authorization) {
        this(Objects.requireNonNull(authorization, "authorization"), false, Map.of(), null, IdpSecurityMetricsRecorder.NOOP, null, null);
    }

    /** Creates a manager from an explicit local policy while retaining the former constructor. */
    public static Rbac3MethodAuthorizationManager createConfigured(AuthorizationService authorization, UserScopePolicyProperties policy,
            IdpObservedVerificationComponent observations, IdpSecurityMetricsRecorder metrics, Validator validator) {
        Objects.requireNonNull(authorization, "authorization");
        new ValidationUtils(Objects.requireNonNull(validator, "defaultValidator")).validate(Objects.requireNonNull(policy, "userScopePolicy"));
        Map<String, Set<String>> scopes = policy.getPermissionScopes().entrySet().stream().collect(java.util.stream.Collectors.toUnmodifiableMap(
                Map.Entry::getKey, entry -> Set.copyOf(entry.getValue())));
        return new Rbac3MethodAuthorizationManager(authorization, policy.isEnabled(), scopes, observations, Objects.requireNonNull(metrics, "metrics"), validator, null);
    }

    public Rbac3MethodAuthorizationManager(AuthorizationService authorization,
            top.egon.cola.platform.tianquan.jianshen.starter.permission.PermissionExecutionGuard compiledPolicy) {
        this(Objects.requireNonNull(authorization, "authorization"), false, Map.of(), null,
                IdpSecurityMetricsRecorder.NOOP, null, Objects.requireNonNull(compiledPolicy, "compiledPolicy"));
    }

    @Override
    public AuthorizationDecision authorize(
            Supplier<? extends Authentication> authentication,
            MethodInvocation invocation) {
        return check(authentication == null ? null : authentication::get, invocation);
    }

    /** Retains the existing entry point while Spring Security 7 calls authorize. */
    public AuthorizationDecision check(
            Supplier<Authentication> authentication,
            MethodInvocation invocation) {
        Objects.requireNonNull(invocation, "invocation");
        Method method = Objects.requireNonNull(invocation.getMethod(), "method");
        Class<?> targetClass = invocation.getThis() == null
                ? method.getDeclaringClass()
                : invocation.getThis().getClass();
        var declaration = resource(method, targetClass);
        if (declaration != null) {
            if (compiledPolicy == null) return new AuthorizationDecision(false);
            var policy = compiledPolicy.resource(declaration.key(), top.egon.cola.platform.tianquan.jianshen.contract.permission.ResourceType.API);
            if (policy.access() != declaration.access() || !sameRequirement(policy.requirement(), groups(method, targetClass))
                    || !Set.copyOf(policy.oauthScopes()).equals(Set.of(declaration.oauthScopes()))
                    || !Set.copyOf(policy.allowedPrincipals()).equals(Set.of(declaration.allowedPrincipals()))) {
                throw new IllegalStateException("COMPILED_PERMISSION_POLICY_MISMATCH");
            }
            if (compiledPolicy.nativeAnonymousBoundary(declaration.key())) return new AuthorizationDecision(true);
            Authentication current = authentication == null ? null : authentication.get();
            if (current != null && current.isAuthenticated() && current.getPrincipal() instanceof ServiceIdentityPrincipal service) {
                compiledPolicy.requireServiceApi(declaration.key(), service);
                return new AuthorizationDecision(true);
            }
            compiledPolicy.require(declaration.key());
            return new AuthorizationDecision(true);
        }
        if (compiledPolicy != null) {
            throw new IllegalStateException("COMPILED_PERMISSION_RESOURCE_MISSING");
        }
        List<PermissionRequest> required = permissions(method, targetClass);
        if (validator != null) { required.forEach(request -> new ValidationUtils(validator).validate(request)); }
        if (userScopesEnabled) {
            Authentication current = authentication == null ? null : authentication.get();
            if (!userScopesAllow(current, required)) {
                scopeDenied(current);
                return new AuthorizationDecision(false);
            }
        }
        for (PermissionRequest request : required) {
            var decision = authorization.requirePermission(request);
            if (decision == null || decision.decision() != Decision.ALLOW) {
                return new AuthorizationDecision(false);
            }
        }
        return new AuthorizationDecision(true);
    }

    private boolean userScopesAllow(Authentication authentication, List<PermissionRequest> required) {
        if (required.isEmpty()) { return true; }
        if (authentication == null || !authentication.isAuthenticated()) { return false; }
        // SERVICE keeps its existing provider scope contract and original downstream authorization.
        if (authentication.getPrincipal() instanceof ServiceIdentityPrincipal) { return true; }
        if (identity(authentication) == null) { return false; }
        Set<String> granted = authentication.getAuthorities().stream().map(org.springframework.security.core.GrantedAuthority::getAuthority)
                .filter(Objects::nonNull).filter(value -> value.startsWith("SCOPE_")).map(value -> value.substring(6))
                .collect(java.util.stream.Collectors.toUnmodifiableSet());
        return required.stream().allMatch(request -> permissionScopes.containsKey(request.permissionCode())
                && granted.containsAll(permissionScopes.get(request.permissionCode())));
    }

    private void scopeDenied(Authentication authentication) {
        try { metrics.record(SecurityMetricObservationBO.builder().signal("rbac.authorization").result("DENY").build()); }
        catch (RuntimeException failure) {
            if (metricFailureLogged.compareAndSet(false, true)) { log.warn("Authorization metric unavailable; failureType={}", failure.getClass().getSimpleName()); }
        }
        if (observations == null || !observations.enabled()) { return; }
        IdentityPrincipal identity = identity(authentication);
        if (identity == null) { return; }
        if (!(authentication.getDetails() instanceof TokenAuditProofBO proof)) {
            throw new AuthorizationService.RuntimeUnavailableException("OAUTH_AUDIT_DELIVERY_UNAVAILABLE", identity);
        }
        boolean confirmed;
        var attributes = RequestContextHolder.getRequestAttributes();
        if (attributes instanceof ServletRequestAttributes servlet) {
            var marker = IdpSecurityObservationFilter.authorizationObservationContext(servlet.getRequest());
            confirmed = marker != null && marker.denyOnce(() -> observations.authorizationDenied(proof));
        } else if (IdpRpcSecurityContext.currentProofOrNull() != null) {
            var marker = IdpRpcSecurityContext.currentAuthorizationObservationContext();
            confirmed = marker != null && marker.denyOnce(() -> observations.authorizationDenied(proof));
        } else { confirmed = observations.authorizationDenied(proof); }
        if (!confirmed) { throw new AuthorizationService.RuntimeUnavailableException("OAUTH_AUDIT_DELIVERY_UNAVAILABLE", identity); }
    }

    private IdentityPrincipal identity(Authentication authentication) {
        if (authentication == null) { return null; }
        if (authentication.getPrincipal() instanceof IdentityPrincipal user) { return user; }
        return authentication.getPrincipal() instanceof Rbac3UserDetails user ? user.identity() : null;
    }

    /** Resolves method/type/API declarations in stable declaration order. */
    List<PermissionRequest> permissions(MethodInvocation invocation) {
        Method method = Objects.requireNonNull(invocation.getMethod(), "method");
        Class<?> targetClass = invocation.getThis() == null
                ? method.getDeclaringClass()
                : invocation.getThis().getClass();
        return permissions(method, targetClass);
    }

    public boolean supports(Method method, Class<?> targetClass) {
        return resource(method, targetClass) != null || !permissions(method, targetClass).isEmpty()
                || !org.springframework.core.annotation.AnnotatedElementUtils.findMergedRepeatableAnnotations(method,
                    top.egon.cola.platform.tianquan.jianshen.contract.permission.annotation.RequiresPermissions.class).isEmpty();
    }

    private List<PermissionRequest> permissions(
            Method method,
            Class<?> targetClass) {
        LinkedHashSet<PermissionRequest> required = new LinkedHashSet<>();
        addGeneric(required, targetClass);
        addGeneric(required, method.getDeclaringClass());
        addGeneric(required, method);
        addApi(required, targetClass);
        addApi(required, method.getDeclaringClass());
        addApi(required, method);
        return List.copyOf(required);
    }

    private boolean sameRequirement(top.egon.cola.platform.tianquan.jianshen.contract.permission.PermissionRequirement left,
            top.egon.cola.platform.tianquan.jianshen.contract.permission.PermissionRequirement right) {
        if (left == null || right == null) return left == right;
        var canonical = new top.egon.cola.platform.tianquan.jianshen.contract.permission.PermissionManifestCanonicalizer();
        return canonical.requirementMap(left).equals(canonical.requirementMap(right));
    }

    private top.egon.cola.platform.tianquan.jianshen.contract.permission.annotation.PermissionResource resource(Method method, Class<?> targetClass) {
        Method specific = org.springframework.aop.support.AopUtils.getMostSpecificMethod(method,
                org.springframework.util.ClassUtils.getUserClass(targetClass));
        return org.springframework.core.annotation.AnnotatedElementUtils.findMergedAnnotation(specific,
                top.egon.cola.platform.tianquan.jianshen.contract.permission.annotation.PermissionResource.class);
    }

    private top.egon.cola.platform.tianquan.jianshen.contract.permission.PermissionRequirement groups(Method method, Class<?> targetClass) {
        var groups = new java.util.ArrayList<top.egon.cola.platform.tianquan.jianshen.contract.permission.PermissionRequirement>();
        for (AnnotatedElement element : List.of(org.springframework.util.ClassUtils.getUserClass(targetClass), method.getDeclaringClass(), method,
                org.springframework.aop.support.AopUtils.getMostSpecificMethod(method, targetClass))) {
            var annotations = org.springframework.core.annotation.AnnotatedElementUtils.findMergedRepeatableAnnotations(element,
                    top.egon.cola.platform.tianquan.jianshen.contract.permission.annotation.RequiresPermissions.class);
            for (var annotation : annotations) {
                var group = new top.egon.cola.platform.tianquan.jianshen.contract.permission.PermissionRequirement(
                        annotation.mode(), List.of(annotation.codes()));
                if (!groups.contains(group)) groups.add(group);
            }
        }
        if (groups.isEmpty()) return null;
        return groups.size() == 1 ? groups.getFirst()
                : top.egon.cola.platform.tianquan.jianshen.contract.permission.PermissionRequirement.allOf(groups);
    }

    private void addApi(
            LinkedHashSet<PermissionRequest> required,
            AnnotatedElement element) {
        RBACAPIResource resource = element.getAnnotation(RBACAPIResource.class);
        if (resource == null) {
            return;
        }
        required(resource.code(), "RBACAPIResource.code");
        String permission = required(
                resource.permission(),
                "RBACAPIResource.permission");
        required(resource.name(), "RBACAPIResource.name");
        required.add(PermissionRequest.api(permission, resource.code()));
    }

    private void addGeneric(
            LinkedHashSet<PermissionRequest> required,
            AnnotatedElement element) {
        RequiresPermission generic = element.getAnnotation(RequiresPermission.class);
        if (generic != null) {
            required.add(PermissionRequest.of(
                    required(generic.value(), "RequiresPermission.value")));
        }
    }

    private String required(String value, String field) {
        if (value == null || value.isBlank() || !value.equals(value.trim())) {
            throw new IllegalArgumentException(field + " is required");
        }
        return value;
    }
}
