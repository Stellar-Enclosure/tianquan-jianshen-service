package top.egon.cola.platform.tianquan.jianshen.starter.permission;

import org.junit.jupiter.api.Test;
import top.egon.cola.platform.tianquan.jianshen.starter.autoconfigure.Rbac3StarterProperties;
import java.util.HashMap;
import java.util.HashSet;
import java.util.Map;
import java.util.Set;
import static org.assertj.core.api.Assertions.*;

class UserPermissionScopePolicyTest {
    @Test void exposesTheImmutableMappingActuallyCapturedByTheGuard() {
        var scopes = new HashSet<>(Set.of("scope:read"));
        var mappings = new HashMap<String, Set<String>>(); mappings.put("order:read", scopes);
        var properties = new Rbac3StarterProperties.UserScopePolicyProperties().setEnabled(true).setPermissionScopes(mappings);
        var policy = new UserPermissionScopePolicy(properties);
        scopes.add("scope:extra"); mappings.put("order:write", Set.of("scope:write")); properties.setEnabled(false);
        assertThat(policy.enabled()).isTrue();
        assertThat(policy.permissionScopes()).containsExactlyEntriesOf(Map.of("order:read", Set.of("scope:read")));
        assertThatThrownBy(() -> policy.permissionScopes().put("x", Set.of("y"))).isInstanceOf(UnsupportedOperationException.class);
    }
}
