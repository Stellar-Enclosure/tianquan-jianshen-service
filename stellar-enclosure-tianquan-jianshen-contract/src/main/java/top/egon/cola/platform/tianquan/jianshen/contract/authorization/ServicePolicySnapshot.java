package top.egon.cola.platform.tianquan.jianshen.contract.authorization;

import com.fasterxml.jackson.annotation.JsonFormat;
import top.egon.cola.platform.tianquan.jianshen.contract.permission.CatalogScope;
import java.time.Instant;
import java.util.Set;
import java.util.Objects;

/** Current deployment policy evidence for a SERVICE receiver; deliberately contains no USER, roles or permission set. */
public record ServicePolicySnapshot(CatalogScope catalogScope, String catalogVersion, String policyVersion,
                                    RuntimePolicyBinding policyBinding, Set<String> resourceKeys,
                                    @JsonFormat(shape=JsonFormat.Shape.STRING) Instant expiresAt) {
    public ServicePolicySnapshot {
        Objects.requireNonNull(catalogScope,"catalogScope"); Objects.requireNonNull(policyBinding,"policyBinding");
        if(catalogVersion==null||!catalogVersion.matches("[1-9][0-9]{0,18}")
                ||policyVersion==null||!policyVersion.matches("0|[1-9][0-9]{0,18}")) throw new IllegalArgumentException("policy versions are invalid");
        Long.parseLong(catalogVersion);Long.parseLong(policyVersion);
        resourceKeys=Set.copyOf(resourceKeys);Objects.requireNonNull(expiresAt,"expiresAt");
        if(resourceKeys.size()>50_000) throw new IllegalArgumentException("policy resources exceed limit");
    }
}
