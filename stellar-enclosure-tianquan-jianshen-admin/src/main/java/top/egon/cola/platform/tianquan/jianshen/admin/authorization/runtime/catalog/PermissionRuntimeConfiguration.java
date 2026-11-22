package top.egon.cola.platform.tianquan.jianshen.admin.authorization.runtime.catalog;

import org.springframework.boot.context.properties.EnableConfigurationProperties;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.context.annotation.Lazy;
import org.springframework.context.annotation.Primary;
import top.egon.cola.platform.tianquan.jianshen.starter.client.Rbac3AuthorizationClient;
import top.egon.cola.platform.tianquan.jianshen.contract.authorization.SystemAuthorizationSnapshot;
import top.egon.cola.platform.tianquan.shoubing.contract.IdentityPrincipal;
import top.egon.cola.platform.tianquan.shoubing.starter.security.VerifiedUserTokenCarrier;

@Configuration(proxyBeanMethods = false)
@EnableConfigurationProperties(PermissionRuntimeProperties.class)
public class PermissionRuntimeConfiguration {
    /** The authority reads its own SQL state; it never recursively calls its authenticated HTTP endpoint. */
    @Bean
    @Primary
    Rbac3AuthorizationClient localCatalogAuthorizationClient(@Lazy PermissionRuntimeProofService proofs,
                                                            @Lazy PermissionRuntimeSnapshotRepository snapshots) {
        return new Rbac3AuthorizationClient() {
            @Override public top.egon.cola.platform.tianquan.jianshen.contract.authorization.ServicePolicySnapshot fetchPolicy(
                    String systemCode, top.egon.cola.platform.tianquan.shoubing.contract.ServiceIdentityPrincipal caller) {
                var authentication = org.springframework.security.core.context.SecurityContextHolder.getContext().getAuthentication();
                if (!(authentication instanceof top.egon.cola.platform.tianquan.shoubing.starter.security.IdpAuthenticationToken token)
                        || token.getPrincipal() != caller) throw new AuthorizationDeniedException("SERVICE_IDENTITY_DENIED");
                try {
                    var binding = proofs.localPolicy(caller, token.verifiedIssuer());
                    if (!binding.scope().applicationCode().equals(systemCode)) throw new AuthorizationDeniedException("APPLICATION_BINDING_DENIED");
                    return snapshots.policy(binding, caller.expiresAt());
                }
                catch (RuntimeException failed) { throw translate(failed); }
            }
            @Override public SystemAuthorizationSnapshot fetch(String systemCode, IdentityPrincipal identity) {
                return fetch(systemCode, identity, VerifiedUserTokenCarrier.current());
            }
            @Override public SystemAuthorizationSnapshot fetch(String systemCode, IdentityPrincipal identity, String rawToken) {
                try {
                    var proof = proofs.local(identity, rawToken);
                    if (!proof.binding().scope().applicationCode().equals(systemCode)) {
                        throw new AuthorizationDeniedException("APPLICATION_BINDING_DENIED");
                    }
                    return snapshots.current(proof);
                } catch (RuntimeException failed) { throw translate(failed); }
            }
        };
    }

    private static RuntimeException translate(RuntimeException failure) {
        if (failure instanceof Rbac3AuthorizationClient.AuthorizationDeniedException
                || failure instanceof Rbac3AuthorizationClient.AuthorizationUnavailableException) return failure;
        if (failure instanceof top.egon.cola.platform.tianquan.jianshen.core.rule.Rbac3RuleViolation violation) {
            String code = violation.reasonCode();
            if (!code.startsWith("AUTH_RUNTIME_") && !code.startsWith("AUTH_SNAPSHOT_")
                    && !java.util.Set.of("AUTH_PROPAGATION_PENDING", "AUTH_VERSION_MISMATCH", "POLICY_VERSION_MISMATCH").contains(code)) {
                var denied = new Rbac3AuthorizationClient.AuthorizationDeniedException(code);
                if ("AUTH_DEPLOYMENT_BINDING_MISMATCH".equals(code)
                        && violation.getCause() instanceof top.egon.cola.platform.tianquan.jianshen.starter.permission.RuntimeBindingMismatchEvidence) {
                    denied.initCause(violation);
                }
                return denied;
            }
        }
        return new Rbac3AuthorizationClient.AuthorizationUnavailableException("AUTH_RUNTIME_UNAVAILABLE", failure);
    }
}
