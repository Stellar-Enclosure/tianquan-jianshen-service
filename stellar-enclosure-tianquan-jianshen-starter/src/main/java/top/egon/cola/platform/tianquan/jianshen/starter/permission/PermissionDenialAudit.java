package top.egon.cola.platform.tianquan.jianshen.starter.permission;

import java.util.function.Supplier;
import java.util.function.Consumer;
import java.time.Clock;
import java.util.Map;
import java.util.Set;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.slf4j.MDC;
import org.springframework.security.authorization.AuthorizationDeniedException;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.web.context.request.RequestContextHolder;
import org.springframework.web.context.request.ServletRequestAttributes;
import top.egon.cola.platform.tianquan.jianshen.starter.client.Rbac3AuthorizationClient;
import top.egon.cola.platform.tianquan.shoubing.starter.security.IdpObservedVerificationComponent;
import top.egon.cola.platform.tianquan.shoubing.starter.security.IdpSecurityObservationFilter;
import top.egon.cola.platform.tianquan.shoubing.starter.security.domain.TokenAuditProofBO;
import top.egon.cola.platform.tianquan.shoubing.starter.security.rpc.IdpRpcSecurityContext;
import top.egon.cola.platform.tianquan.jianshen.contract.authorization.SystemAuthorizationSnapshot;
import top.egon.cola.platform.tianquan.jianshen.contract.permission.PermissionManifest;
import top.egon.cola.platform.tianquan.jianshen.contract.permission.PermissionManifestCanonicalizer;
import top.egon.cola.platform.tianquan.jianshen.contract.permission.PermissionRequirement;
import top.egon.cola.platform.tianquan.jianshen.contract.permission.PermissionMode;

/** Reuses the existing per-invocation strict audit marker for compiled API, field and alternative-entry denials. */
public final class PermissionDenialAudit {
    public static final PermissionDenialAudit UNOBSERVED = new PermissionDenialAudit(() -> null);
    private static final Logger LOG = LoggerFactory.getLogger(PermissionDenialAudit.class);
    private static final String DECISION_ATTRIBUTE = PermissionDenialAudit.class.getName() + ".decisionId";
    private final Supplier<IdpObservedVerificationComponent> observations;
    private final Consumer<PermissionDenialDiagnostic> diagnostics;
    private final Clock clock;

    public PermissionDenialAudit(Supplier<IdpObservedVerificationComponent> observations) {
        this(observations, ignored -> { }, Clock.systemUTC());
    }

    public PermissionDenialAudit(Supplier<IdpObservedVerificationComponent> observations,
                                 Consumer<PermissionDenialDiagnostic> diagnostics, Clock clock) {
        this.observations = java.util.Objects.requireNonNull(observations, "observations");
        this.diagnostics = java.util.Objects.requireNonNull(diagnostics, "diagnostics");
        this.clock = java.util.Objects.requireNonNull(clock, "clock");
    }

    public RuntimeException denied(String reason) {
        return denied(reason, reason, null);
    }

    public RuntimeException denied(String reason, String diagnosticReason, String resourceKey) {
        return denied(reason, diagnosticReason, resourceKey, null);
    }

    public RuntimeException denied(String reason, String diagnosticReason, String resourceKey,
            top.egon.cola.platform.tianquan.jianshen.contract.authorization.SystemAuthorizationSnapshot evidence) {
        return denied(reason, diagnosticReason, resourceKey, evidence, null, null, null, null);
    }

    public RuntimeException denied(String reason, String diagnosticReason, String resourceKey,
            SystemAuthorizationSnapshot evidence, PermissionManifest.ResourceDefinition policy,
            Set<String> qualified, Set<String> scopes, UserPermissionScopePolicy scopePolicy) {
        return denied(reason, diagnosticReason, resourceKey, evidence, policy, policy == null ? null : policy.requirement(),
                qualified, scopes, scopePolicy, "API", Map.of(), true);
    }

    public RuntimeException deniedField(String diagnosticReason, PermissionManifest.ResourceDefinition field,
            SystemAuthorizationSnapshot evidence, Set<String> qualified, Set<String> scopes,
            UserPermissionScopePolicy scopePolicy, boolean inputWritable) {
        var rule = field.fieldPolicy() == null ? null : field.fieldPolicy().write();
        return denied("FIELD_ACCESS_DENIED", diagnosticReason, field.key(), evidence, field, rule, qualified, scopes,
                scopePolicy, "FIELD_WRITE", Map.of("inputBindingWritable", inputWritable, "fieldAccess", field.access().name()), true);
    }

    public RuntimeException deniedBinding(String reason, String resourceKey, SystemAuthorizationSnapshot evidence,
            PermissionPolicyRegistry registry) {
        Map<String, Object> details;
        try { details = registry.bindingFailureDetails(evidence, resourceKey); }
        catch (RuntimeException failure) { details = Map.of(); }
        return denied(reason, reason, resourceKey, evidence, null, null, null, null, null,
                "DEPLOYMENT_BINDING", details, false);
    }

    public RuntimeException deniedFieldInput(String reason, String apiKey, SystemAuthorizationSnapshot evidence,
                                             PermissionPolicyRegistry registry) {
        boolean trusted = false;
        try {
            if (apiKey != null && registry.trustedScope(evidence)) {
                registry.requireActive(evidence, apiKey);
                trusted = true;
            }
        } catch (RuntimeException failure) {
            LOG.warn("Field input diagnostic unavailable failureType={}", failure.getClass().getSimpleName());
        }
        return trusted ? denied(reason, reason, apiKey, evidence, null, null, null, null, null,
                "FIELD_INPUT", Map.of("fieldKeyAvailable", false, "stage", "INPUT_BINDING"), false) : denied(reason);
    }

    private RuntimeException denied(String reason, String diagnosticReason, String resourceKey,
            SystemAuthorizationSnapshot evidence, PermissionManifest.ResourceDefinition policy, PermissionRequirement requirement,
            Set<String> qualified, Set<String> scopes, UserPermissionScopePolicy scopePolicy,
            String kind, Map<String, Object> details, boolean resolveSources) {
        boolean confirmed = true;
        if (RequestContextHolder.getRequestAttributes() instanceof ServletRequestAttributes servlet) {
            confirmed = IdpSecurityObservationFilter.beforeAuthorizationDenied(servlet.getRequest());
        } else {
            var observer = observations.get();
            if (observer != null && observer.enabled()) {
                var authentication = SecurityContextHolder.getContext().getAuthentication();
                TokenAuditProofBO proof = IdpRpcSecurityContext.currentProofOrNull();
                if (proof == null && authentication != null && authentication.getDetails() instanceof TokenAuditProofBO proofDetails) proof = proofDetails;
                if (proof == null) confirmed = false;
                else {
                    var verified = proof;
                    var marker = IdpRpcSecurityContext.currentAuthorizationObservationContext();
                    confirmed = marker == null ? observer.authorizationDenied(verified)
                            : marker.denyOnce(() -> observer.authorizationDenied(verified));
                }
            }
        }
        observe(confirmed ? diagnosticReason : "OAUTH_AUDIT_DELIVERY_UNAVAILABLE", resourceKey, evidence,
                confirmed ? policy : null, confirmed ? requirement : null, qualified, scopes, scopePolicy,
                confirmed ? kind : "UNAVAILABLE", confirmed ? details : Map.of(), resolveSources);
        return confirmed ? new AuthorizationDeniedException(reason)
                : new Rbac3AuthorizationClient.AuthorizationUnavailableException("OAUTH_AUDIT_DELIVERY_UNAVAILABLE");
    }

    /** The caller has already completed the existing strict audit handoff; this is an intermediate scope result. */
    public void observedDataScopeDenied(top.egon.cola.platform.tianquan.jianshen.contract.authorization.DataScopeDecision decision,
            SystemAuthorizationSnapshot snapshot, PermissionPolicyRegistry registry) {
        try {
            var current = new top.egon.cola.platform.tianquan.jianshen.starter.security.CurrentRbac3User().current().orElse(null);
            String apiKey = PermissionExecutionContext.currentApiKeyOrNull();
            if (current == null || current.snapshot() != snapshot || apiKey == null || !registry.trustedScope(snapshot)
                    || !snapshot.tenantId().equals(decision.tenantId()) || !snapshot.rbac3UserId().equals(decision.subjectId())
                    || snapshot.authVersion() != decision.authVersion() || snapshot.policyVersion() != decision.policyVersion()
                    || decision.decision() != top.egon.cola.platform.tianquan.jianshen.contract.authorization.Decision.DENY
                    || !decision.permissionCode().matches("[A-Za-z0-9._:/-]{1,128}")) return;
            registry.requireActive(snapshot, apiKey);
            var rule = new PermissionRequirement(PermissionMode.ALL, java.util.List.of(decision.permissionCode()));
            String scopeType = decision.scopeType().matches("[A-Z0-9_]{1,64}") ? decision.scopeType() : "UNAVAILABLE";
            String directoryVersion = decision.directorySnapshotVersion().matches("[A-Za-z0-9._:~-]{1,128}")
                    ? decision.directorySnapshotVersion() : "unavailable";
            observe(decision.reasonCode(), apiKey, snapshot, null, rule, Set.of(), Set.of(), null,
                    "DATA_SCOPE_POLICY", Map.of("scopeType", scopeType, "directoryVersion", directoryVersion,
                            "decisionVersion", decision.decisionVersion(), "finalObjectDecision", false,
                            "scopeEvaluation", "NOT_EVALUATED"), true);
        } catch (RuntimeException failure) {
            LOG.warn("Data scope diagnostic unavailable failureType={}", failure.getClass().getSimpleName());
        }
    }

    /** The local Runtime has verified the USER; the caller has already confirmed its strict denial audit. */
    public void observedRuntimeBindingDenied(Rbac3AuthorizationClient.AuthorizationDeniedException failure,
            top.egon.cola.platform.tianquan.shoubing.contract.IdentityPrincipal identity,
            jakarta.servlet.http.HttpServletRequest request, jakarta.servlet.http.HttpServletResponse response,
            String resourceKey) {
        String decisionId = null;
        try {
            if (!"AUTH_DEPLOYMENT_BINDING_MISMATCH".equals(failure.getMessage()) || identity == null || request == null
                    || failure.getCause() == null || !(failure.getCause().getCause() instanceof RuntimeBindingMismatchEvidence evidence)
                    || !identity.tenantId().equals(evidence.scope().tenantId())) return;
            decisionId = decisionId(request, response);
            String traceId = MDC.get("traceId");
            if (traceId == null || !traceId.matches("[A-Za-z0-9._~-]{1,128}")) traceId = "unavailable";
            String resource = resourceKey != null && resourceKey.matches("[A-Za-z0-9._:/-]{1,200}") ? resourceKey : "unavailable";
            String subjectHash = "sha256:" + java.util.HexFormat.of().formatHex(java.security.MessageDigest.getInstance("SHA-256")
                    .digest(identity.subject().getBytes(java.nio.charset.StandardCharsets.UTF_8)));
            var now = clock.instant();
            LOG.info("Runtime binding denied decisionId={} traceId={} catalogVersion={} policyVersion={} producerId={}",
                    decisionId, traceId, evidence.catalogVersion(), evidence.policyVersion(), evidence.selected().producerId());
            diagnostics.accept(new PermissionDenialDiagnostic(decisionId, traceId, "AUTH_DEPLOYMENT_BINDING_MISMATCH", resource,
                    subjectHash, evidence.scope(), evidence.catalogVersion(), "unavailable", evidence.policyVersion(),
                    java.util.List.of(), java.util.List.of(), Map.of(), java.util.List.of(), java.util.List.of(),
                    evidence.selected(), now, now, "RUNTIME_BINDING", Map.of("snapshotAvailable", false,
                            "actorIdentifierKind", "SUBJECT_SHA256", "configuredProducer", evidence.configuredProducer(),
                            "failedChecks", evidence.failedChecks()), false));
        } catch (java.security.NoSuchAlgorithmException | RuntimeException failureToRecord) {
            LOG.warn("Runtime binding diagnostic unavailable decisionId={} failureType={}", decisionId, failureToRecord.getClass().getSimpleName());
        }
    }

    private void observe(String reason, String resourceKey, SystemAuthorizationSnapshot evidence,
            PermissionManifest.ResourceDefinition policy, PermissionRequirement requirement, Set<String> qualified, Set<String> scopes,
            UserPermissionScopePolicy scopePolicy, String kind, Map<String, Object> diagnosticDetails, boolean resolveSources) {
        String decisionId = null;
        if (RequestContextHolder.getRequestAttributes() instanceof ServletRequestAttributes servlet) {
            decisionId = decisionId(servlet.getRequest(), servlet.getResponse());
        }
        if (decisionId == null) decisionId = java.util.UUID.randomUUID().toString();
        String traceId = MDC.get("traceId");
        if (traceId == null || !traceId.matches("[A-Za-z0-9._~-]{1,128}")) traceId = "unavailable";
        String code = reason != null && reason.matches("[A-Z0-9_]{1,96}") ? reason : "AUTHORIZATION_DENIED";
        String resource = resourceKey != null && resourceKey.matches("[A-Za-z0-9._:/-]{1,200}") ? resourceKey : "unavailable";
        var details = new top.egon.cola.platform.tianquan.jianshen.starter.security.CurrentRbac3User().current().orElse(null);
        var snapshot = evidence != null ? evidence : details == null ? null : details.snapshot();
        var view = snapshot == null ? null : snapshot.permissionSnapshot();
        var binding = snapshot == null ? null : snapshot.policyBinding();
        LOG.info("Permission denied decisionId={} traceId={} reasonCode={} resourceKey={} evidenceSource={} catalogVersion={} authVersion={} policyVersion={} producerId={} producerVersion={} manifestDigest={} artifactDigest={}",
                decisionId, traceId, code, resource, evidence != null ? "DECISION" : snapshot != null ? "REQUEST_CONTEXT" : "UNAVAILABLE",
                view == null ? null : view.catalogVersion(), view == null ? null : view.authVersion(),
                view == null ? null : view.policyVersion(), binding == null ? null : binding.producerId(),
                binding == null ? null : binding.producerVersion(), binding == null ? null : binding.manifestDigest(),
                binding == null ? null : binding.artifactDigest());
        if (evidence == null || view == null || binding == null || "UNAVAILABLE".equals(kind)) return;
        if ("DEPLOYMENT_BINDING".equals(kind) && diagnosticDetails.isEmpty()) return;
        if (("API".equals(kind) || "FIELD_WRITE".equals(kind))
                && (policy == null || qualified == null || scopes == null || scopePolicy == null || !policy.key().equals(resourceKey))) return;
        try {
            var codes = requirement == null ? java.util.List.<String>of() : requirement.groups().stream()
                    .flatMap(group -> group.codes().stream()).distinct().sorted().toList();
            var facts = codes.stream().map(permission -> new PermissionDenialDiagnostic.PermissionFact(
                    permission, evidence.permissions().contains(permission), qualified != null && qualified.contains(permission),
                    scopePolicy != null && scopePolicy.hasScopeMapping(permission), scopePolicy == null ? java.util.List.of()
                    : scopePolicy.missingScopes(permission, scopes).stream().sorted().toList())).toList();
            var missingScopes = policy == null || UserPermissionScopePolicy.mixed(policy) ? java.util.List.<String>of()
                    : policy.oauthScopes().stream().filter(scope -> !scopes.contains(scope)).sorted().toList();
            diagnostics.accept(new PermissionDenialDiagnostic(decisionId, traceId, code, resource, evidence.rbac3UserId(),
                    view.catalogScope(), view.catalogVersion(), view.authVersion(), view.policyVersion(),
                    resolveSources ? view.activeRoleContext().rootRoleIds() : java.util.List.of(),
                    resolveSources ? view.activeRoleContext().effectiveRoleIds() : java.util.List.of(),
                    requirement == null ? java.util.Map.of() : new PermissionManifestCanonicalizer().requirementMap(requirement),
                    facts, missingScopes, binding, evidence.generatedAt(), clock.instant(), kind, diagnosticDetails, resolveSources));
        } catch (RuntimeException failed) {
            LOG.warn("Permission diagnostic persistence failed decisionId={} failureType={}", decisionId, failed.getClass().getSimpleName());
        }
    }

    private static String decisionId(jakarta.servlet.http.HttpServletRequest request,
                                     jakarta.servlet.http.HttpServletResponse response) {
        Object existing = request.getAttribute(DECISION_ATTRIBUTE);
        String id = existing instanceof String value ? value : java.util.UUID.randomUUID().toString();
        request.setAttribute(DECISION_ATTRIBUTE, id);
        if (response != null && !response.isCommitted()) response.setHeader("X-Permission-Decision-Id", id);
        return id;
    }
}
