package top.egon.cola.platform.tianquan.jianshen.contract.authorization;

import com.fasterxml.jackson.databind.ObjectMapper;
import org.junit.jupiter.api.Test;

import java.time.Instant;
import java.util.List;
import java.util.Map;
import java.util.Set;

import static org.junit.jupiter.api.Assertions.*;

class ExecutionScopeAuthorizationContractTest {
    private static final Instant NOW = Instant.parse("2026-10-31T00:00:00Z");

    @Test
    void the_original_response_shape_is_unchanged_and_scopes_bind_the_internal_rbac_user_separately() throws Exception {
        var base = base(); var mapper = new ObjectMapper().findAndRegisterModules();
        assertEquals(13, mapper.readTree(mapper.writeValueAsBytes(base)).size());
        var scoped = new ExecutionScopeAuthorizationContract.Decision(base, "60", NOW, Map.of("MEMORY_READ", scope("60", "20", 2, NOW)));
        assertEquals("identity-sub", scoped.execution().subject()); assertEquals("60", scoped.dataScopes().get("MEMORY_READ").subjectId());
        assertThrows(UnsupportedOperationException.class, () -> scoped.dataScopes().clear()); assertFalse(scoped.toString().contains("identity-sub"));
    }

    @Test
    void foreign_tenant_subject_version_permission_and_timestamp_data_are_refused() {
        for (var scope : List.of(scope("identity-sub", "20", 2, NOW), scope("60", "21", 2, NOW), scope("60", "20", 3, NOW), scope("60", "20", 2, NOW.minusSeconds(1)))) {
            assertThrows(IllegalArgumentException.class, () -> new ExecutionScopeAuthorizationContract.Decision(base(), "60", NOW, Map.of("MEMORY_READ", scope)));
        }
        assertThrows(IllegalArgumentException.class, () -> new ExecutionScopeAuthorizationContract.Decision(base(), "60", NOW, Map.of("ANOTHER_PERMISSION", scope("60", "20", 2, NOW))));
    }
    private static ExecutionAuthorizationContract.Decision base() {
        return new ExecutionAuthorizationContract.Decision("9" + "1".repeat(62), "https://idp.example/20", "20", "identity-sub", "https://agent.example", "TIANJI_MEMORY_READ",
                "00000000-0000-0000-0000-000000000123", "a".repeat(64), false, NOW.plusSeconds(60), NOW.plusSeconds(30), 2, 3);
    }
    private static DataScopeDecision scope(String subject, String tenant, long auth, Instant now) {
        return new DataScopeDecision(Decision.ALLOW, "ALLOW", tenant, subject, "MEMORY_READ", "CUSTOM", false, Set.of("17"), false, Set.of(), false,
                Set.of(), false, null, "1", 3, auth, 3, List.of(), now);
    }
}
