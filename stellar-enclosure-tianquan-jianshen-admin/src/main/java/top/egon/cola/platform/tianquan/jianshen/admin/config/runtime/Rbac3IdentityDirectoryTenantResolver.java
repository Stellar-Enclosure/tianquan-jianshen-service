package top.egon.cola.platform.tianquan.jianshen.admin.config.runtime;

import lombok.NonNull;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Qualifier;
import org.springframework.lang.Nullable;
import org.springframework.security.access.AccessDeniedException;
import org.springframework.security.core.Authentication;
import org.springframework.stereotype.Component;
import top.egon.cola.component.rpc.consumer.interceptor.RpcClientInvocation;
import top.egon.cola.platform.tianquan.jianshen.admin.shared.tenant.domain.TenantContext;
import top.egon.cola.platform.tianquan.jianshen.starter.security.Rbac3AuthenticationToken;
import top.egon.cola.platform.tianquan.shoubing.rpc.contract.IdentityDirectoryRpc;
import top.egon.cola.platform.tianquan.shoubing.rpc.contract.proto.v1.IdentityDirectoryServiceGrpc;
import top.egon.cola.platform.tianquan.shoubing.starter.security.IdpAuthenticationToken;
import top.egon.cola.platform.tianquan.shoubing.starter.security.domain.TokenAuditProofBO;
import top.egon.cola.platform.tianquan.shoubing.starter.security.rpc.IdpRpcClientTenantResolver;
import top.egon.cola.platform.tianquan.shoubing.starter.security.rpc.IdpRpcSecurityContext;

import java.time.Clock;
import java.util.Objects;
import java.util.Optional;
import java.util.Set;

/** Bridges the authenticated Jianshen request scope to the two directory credential bindings. */
@Slf4j
@Component("idpRpcClientTenantResolver")
@RequiredArgsConstructor(onConstructor_ = @Autowired)
public final class Rbac3IdentityDirectoryTenantResolver implements IdpRpcClientTenantResolver {

    private static final Set<String> METHODS = Set.of(
            IdentityDirectoryServiceGrpc.getGetTenantMembershipMethod().getFullMethodName(),
            IdentityDirectoryServiceGrpc.getBatchGetIdentityProfilesMethod().getFullMethodName());

    @NonNull
    @Qualifier("idpClock")
    private final Clock clock;

    @Override
    public Optional<String> resolve(RpcClientInvocation invocation, @Nullable Authentication authentication) {
        if (!targetsIdentityDirectory(invocation)) {
            return Optional.empty();
        }
        TenantContext tenant = TenantContext.currentOrNull();
        if (authentication instanceof IdpAuthenticationToken idp && idp.isAuthenticated()) {
            if (tenant != null && (tenant.platformTarget() || !Objects.equals(idp.getPrincipal().tenantId(), tenant.effectiveTenantId()))) {
                throw denied();
            }
            return Optional.empty();
        }
        return Optional.of(authorizedJianshenTenant(authentication));
    }

    String authorizedJianshenTenant(@Nullable Authentication authentication) {
        TenantContext tenant = TenantContext.currentOrNull();
        if (!(authentication instanceof Rbac3AuthenticationToken rbac) || !rbac.isAuthenticated()
                || !(rbac.getDetails() instanceof TokenAuditProofBO proof) || tenant == null
                || IdpRpcSecurityContext.currentPrincipalOrNull() != null) {
            throw denied();
        }
        var user = rbac.getPrincipal();
        if (!user.identity().expiresAt().isAfter(clock.instant())
                || !user.identity().audience().contains(proof.resource().toString())
                || !user.tenantId().equals(tenant.authenticatedTenantId())
                || tenant.effectiveTenantId() == null || !tenant.effectiveTenantId().matches("[A-Za-z0-9._:-]{1,128}")) {
            throw denied();
        }
        if (tenant.platformTarget()) {
            if (!user.hasPermission("system:platform:admin") || !user.hasPermission("system:tenant:target")) {
                throw denied();
            }
        } else if (!user.tenantId().equals(tenant.effectiveTenantId())) {
            throw denied();
        }
        return tenant.effectiveTenantId();
    }

    private static boolean targetsIdentityDirectory(RpcClientInvocation invocation) {
        return invocation.target() != null && "shoubing-identity-directory".equals(invocation.target().bindingId())
                && IdentityDirectoryServiceGrpc.SERVICE_NAME.equals(invocation.serviceName())
                && IdentityDirectoryRpc.GROUP.equals(invocation.group()) && IdentityDirectoryRpc.VERSION.equals(invocation.version())
                && METHODS.contains(invocation.fullMethodName());
    }

    private static AccessDeniedException denied() {
        log.debug("Jianshen outbound directory tenant was not authorized");
        return new AccessDeniedException("Identity directory tenant is not authorized");
    }
}
