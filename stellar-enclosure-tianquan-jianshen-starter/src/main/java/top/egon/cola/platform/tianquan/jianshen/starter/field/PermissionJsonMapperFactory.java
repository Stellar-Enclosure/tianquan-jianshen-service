package top.egon.cola.platform.tianquan.jianshen.starter.field;

import com.fasterxml.jackson.databind.ObjectMapper;
import top.egon.cola.component.common.desensitize.strategy.SensitiveStrategyRegistry;
import top.egon.cola.platform.tianquan.jianshen.starter.permission.PermissionPolicyRegistry;
import top.egon.cola.platform.tianquan.jianshen.starter.security.CurrentRbac3User;

/** Creates a transport-only mapper; internal persistence and RPC codecs retain their original field semantics. */
public final class PermissionJsonMapperFactory {
    private final CurrentRbac3User users;
    private final SensitiveStrategyRegistry maskers;
    private final PermissionPolicyRegistry policies;
    private final PermissionFieldBindingGuard writes;

    public PermissionJsonMapperFactory(CurrentRbac3User users, SensitiveStrategyRegistry maskers,
            PermissionPolicyRegistry policies, PermissionFieldBindingGuard writes) {
        this.users = users; this.maskers = maskers; this.policies = policies; this.writes = writes;
    }

    public ObjectMapper forTransport(ObjectMapper original) {
        return java.util.Objects.requireNonNull(original, "original").copy()
                .registerModule(new Rbac3FieldJacksonModule(users, maskers, policies, writes));
    }
}
