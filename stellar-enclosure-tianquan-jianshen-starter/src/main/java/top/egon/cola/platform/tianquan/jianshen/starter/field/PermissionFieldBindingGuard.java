package top.egon.cola.platform.tianquan.jianshen.starter.field;

import org.springframework.security.authorization.AuthorizationDeniedException;
import org.springframework.security.core.context.SecurityContextHolder;
import top.egon.cola.platform.tianquan.jianshen.contract.permission.*;
import top.egon.cola.platform.tianquan.jianshen.starter.permission.*;
import top.egon.cola.platform.tianquan.jianshen.starter.security.CurrentRbac3User;
import top.egon.cola.platform.tianquan.shoubing.contract.ServiceIdentityPrincipal;
import java.util.Set;

/** JSON and alternative binders validate every submitted property before a business write. */
public final class PermissionFieldBindingGuard {
    private final PermissionPolicyRegistry registry;
    private final CurrentRbac3User users;
    private final java.util.function.Supplier<PermissionServicePolicyGuard> services;
    private final UserPermissionScopePolicy userScopes;
    private final PermissionDenialAudit audit;
    private final PermissionAnonymousBoundary anonymous;
    private final com.fasterxml.jackson.databind.ObjectMapper metadata = new com.fasterxml.jackson.databind.ObjectMapper();

    public PermissionFieldBindingGuard(PermissionPolicyRegistry registry, CurrentRbac3User users) { this(registry, users, () -> null); }
    public PermissionFieldBindingGuard(PermissionPolicyRegistry registry, CurrentRbac3User users, PermissionServicePolicyGuard services) {
        this(registry, users, () -> services);
    }
    public PermissionFieldBindingGuard(PermissionPolicyRegistry registry, CurrentRbac3User users,
            java.util.function.Supplier<PermissionServicePolicyGuard> services) {
        this(registry, users, services, new top.egon.cola.platform.tianquan.jianshen.starter.autoconfigure.Rbac3StarterProperties.UserScopePolicyProperties());
    }
    public PermissionFieldBindingGuard(PermissionPolicyRegistry registry, CurrentRbac3User users,
            java.util.function.Supplier<PermissionServicePolicyGuard> services,
            top.egon.cola.platform.tianquan.jianshen.starter.autoconfigure.Rbac3StarterProperties.UserScopePolicyProperties scopePolicy) {
        this(registry, users, services, scopePolicy, PermissionDenialAudit.UNOBSERVED);
    }
    public PermissionFieldBindingGuard(PermissionPolicyRegistry registry, CurrentRbac3User users,
            java.util.function.Supplier<PermissionServicePolicyGuard> services,
            top.egon.cola.platform.tianquan.jianshen.starter.autoconfigure.Rbac3StarterProperties.UserScopePolicyProperties scopePolicy,
            PermissionDenialAudit audit) {
        this(registry, users, services, scopePolicy, audit, null);
    }
    public PermissionFieldBindingGuard(PermissionPolicyRegistry registry, CurrentRbac3User users,
            java.util.function.Supplier<PermissionServicePolicyGuard> services,
            top.egon.cola.platform.tianquan.jianshen.starter.autoconfigure.Rbac3StarterProperties.UserScopePolicyProperties scopePolicy,
            PermissionDenialAudit audit, PermissionAnonymousBoundary anonymous) {
        this.registry = registry; this.users = users; this.services = services;
        this.userScopes = new UserPermissionScopePolicy(scopePolicy); this.audit = audit; this.anonymous = anonymous;
    }

    boolean anonymousRead(PermissionManifest.ResourceDefinition field, boolean readOnly) {
        return anonymous != null && anonymous.readOnlyField(field, readOnly);
    }

    RuntimeException denyInput(String reason) { return audit.denied(reason); }

    public void require(Class<?> dto, SubmittedFieldSet submitted, Set<String> writableBindings) {
        try { requireFields(dto, submitted, writableBindings); }
        catch (AuthorizationDeniedException denied) { throw audit.denied(denied.getMessage()); }
        catch (top.egon.cola.platform.tianquan.jianshen.starter.client.Rbac3AuthorizationClient.AuthorizationDeniedException denied) {
            throw audit.denied(denied.getMessage());
        }
    }

    private void requireFields(Class<?> dto, SubmittedFieldSet submitted, Set<String> writableBindings) {
        var fields = registry.fields(dto);
        if (fields.isEmpty() && submitted.paths().isEmpty()) return;
        var authentication = SecurityContextHolder.getContext().getAuthentication();
        ServiceIdentityPrincipal service = authentication != null && authentication.isAuthenticated()
                && authentication.getPrincipal() instanceof ServiceIdentityPrincipal caller ? caller : null;
        var user = service == null ? users.require() : null;
        for (String property : submitted.paths()) {
            var field = fields.get(property);
            if (field == null) throw new AuthorizationDeniedException("FIELD_BINDING_UNDECLARED");
            boolean input = writableBindings.contains(property) && !readOnly(dto, property);
            if (service != null) {
                requireService(field, service, true);
                if (!input || field.access() != ResourceAccess.PUBLIC
                        && (field.fieldPolicy() == null || field.fieldPolicy().write() == null)) {
                    throw new AuthorizationDeniedException("FIELD_ACCESS_DENIED");
                }
            } else {
                registry.requireActive(user.snapshot(), field.key());
                Set<String> scopes = UserPermissionScopePolicy.currentScopes();
                if (!userScopes.explicitScopesAllow(field, scopes)
                        || !PermissionFieldPolicy.writable(field, userScopes.qualify(field, user.permissions(), scopes), input)) {
                    throw new AuthorizationDeniedException("FIELD_ACCESS_DENIED");
                }
            }
        }
        if (user != null && !submitted.paths().isEmpty()) PermissionExecutionContext.rememberInput(user.snapshot());
    }

    PermissionFieldPolicy.Read userRead(PermissionManifest.ResourceDefinition field,
            top.egon.cola.platform.tianquan.jianshen.starter.security.Rbac3UserDetails user) {
        Set<String> scopes = UserPermissionScopePolicy.currentScopes();
        if (!userScopes.explicitScopesAllow(field, scopes)) return PermissionFieldPolicy.Read.OMIT;
        return PermissionFieldPolicy.read(field, userScopes.qualify(field, user.permissions(), scopes));
    }

    PermissionFieldPolicy.Read serviceRead(PermissionManifest.ResourceDefinition field, ServiceIdentityPrincipal service) {
        try { requireService(field, service, false); }
        catch (AuthorizationDeniedException denied) { throw audit.denied(denied.getMessage()); }
        catch (top.egon.cola.platform.tianquan.jianshen.starter.client.Rbac3AuthorizationClient.AuthorizationDeniedException denied) {
            throw audit.denied(denied.getMessage());
        }
        if (field.access() == ResourceAccess.PUBLIC) return PermissionFieldPolicy.Read.PLAIN;
        var policy = field.fieldPolicy();
        if (policy == null) return PermissionFieldPolicy.Read.OMIT;
        if (policy.plainRead() != null) return PermissionFieldPolicy.Read.PLAIN;
        return policy.maskedRead() != null ? PermissionFieldPolicy.Read.MASKED : PermissionFieldPolicy.Read.OMIT;
    }

    private void requireService(PermissionManifest.ResourceDefinition field, ServiceIdentityPrincipal caller, boolean write) {
        if (!field.allowedPrincipals().contains(PermissionManifest.PrincipalType.SERVICE)
                || field.oauthScopes().isEmpty() || !caller.scopes().containsAll(field.oauthScopes())) {
            throw new AuthorizationDeniedException("FIELD_SERVICE_SCOPE_DENIED");
        }
        var api = registry.require(PermissionExecutionContext.currentApiKey(), ResourceType.API);
        if (!api.allowedPrincipals().contains(PermissionManifest.PrincipalType.SERVICE) || api.oauthScopes().isEmpty()
                || !caller.scopes().containsAll(api.oauthScopes())) throw new AuthorizationDeniedException("SERVICE_SCOPE_DENIED");
        if (write) {
            Object methods = api.target().get("methods");
            if (!(methods instanceof java.util.List<?> declared)
                    || declared.stream().noneMatch(method -> Set.of("POST", "PUT", "PATCH", "DELETE").contains(method))) {
                throw new AuthorizationDeniedException("FIELD_WRITE_ENTRY_REQUIRED");
            }
        }
        if (!write && registry.bootstrapServiceResource(api.key())) {
            if (!PermissionExecutionContext.verifiedService(caller) || !registry.bootstrapResponseField(api.key(), field)) {
                throw new AuthorizationDeniedException("BOOTSTRAP_RESPONSE_FIELD_DENIED");
            }
            registry.requireBootstrapServiceIdentity(caller);
            return;
        }
        var servicePolicies = services.get();
        if (servicePolicies == null) throw new AuthorizationDeniedException("FIELD_SERVICE_SCOPE_DENIED");
        var current = servicePolicies.require(caller, api.key());
        registry.requireActive(current, field.key());
        if (write) PermissionExecutionContext.rememberInput(current);
    }

    private boolean readOnly(Class<?> dto, String name) {
        for (var property : metadata.getDeserializationConfig().introspect(metadata.constructType(dto)).findProperties()) {
            if (!name.equals(property.getName())) continue;
            for (var member : new com.fasterxml.jackson.databind.introspect.AnnotatedMember[]{property.getPrimaryMember(),
                    property.getField(), property.getGetter(), property.getSetter(), property.getConstructorParameter()}) {
                if (member == null) continue;
                var annotation = member.getAnnotation(com.fasterxml.jackson.annotation.JsonProperty.class);
                if (annotation != null && annotation.access() == com.fasterxml.jackson.annotation.JsonProperty.Access.READ_ONLY) return true;
            }
            return !property.couldDeserialize();
        }
        return true;
    }
}
