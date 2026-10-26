package top.egon.cola.platform.tianquan.jianshen.contract;

import com.fasterxml.jackson.core.type.TypeReference;
import com.fasterxml.jackson.databind.ObjectMapper;
import org.junit.jupiter.api.Test;
import top.egon.cola.platform.tianquan.jianshen.contract.permission.PermissionManifestReader;
import top.egon.cola.platform.tianquan.jianshen.contract.permission.PermissionMode;
import top.egon.cola.platform.tianquan.jianshen.contract.permission.PermissionRequirement;

import java.util.List;
import java.util.Map;
import java.util.Set;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

class PermissionRequirementContractTest {

    @Test
    void sharedTruthTableIncludesOuterAndPublicAndUnknownCodes() throws Exception {
        List<Map<String, Object>> cases;
        try (var input = getClass().getResourceAsStream("/permission-contract/requirements-v1.json")) {
            cases = new ObjectMapper().readValue(input, new TypeReference<>() { });
        }
        var reader = new PermissionManifestReader();
        assertEquals(8, cases.size());
        for (Map<String, Object> test : cases) {
            @SuppressWarnings("unchecked")
            Set<String> effective = Set.copyOf((List<String>) test.get("effective"));
            assertEquals(test.get("allow"), reader.requirement(test.get("requirement")).allows(effective),
                    String.valueOf(test.get("name")));
        }
    }

    @Test
    void emptyOrMixedGroupsCannotGrantAccess() {
        var reader = new PermissionManifestReader();
        assertThrows(IllegalArgumentException.class, () -> new PermissionRequirement(PermissionMode.ALL, List.of()));
        assertThrows(IllegalArgumentException.class, () -> new PermissionRequirement(PermissionMode.ANY, List.of()));
        assertThrows(IllegalArgumentException.class, () -> PermissionRequirement.allOf(List.of()));
        assertThrows(IllegalArgumentException.class, () -> reader.requirement(Map.of("codes", List.of("order:read"))));
        assertThrows(IllegalArgumentException.class, () -> reader.requirement(Map.of("mode", "XOR", "codes", List.of("order:read"))));
        assertThrows(IllegalArgumentException.class, () -> reader.requirement(Map.of("access", "PUBLIC", "mode", "ALL")));
    }

    @Test
    void independentlyGrantedRolesCanSatisfyDifferentConjunctionGroups() {
        var requirement = PermissionRequirement.allOf(List.of(
                new PermissionRequirement(PermissionMode.ALL, List.of("order:read")),
                new PermissionRequirement(PermissionMode.ANY, List.of("order:approve", "order:write"))));
        assertTrue(requirement.allows(Set.of("order:read", "order:approve")));
        assertFalse(requirement.allows(Set.of("order:read")));
    }

    @Test
    void duplicateAndCaseOnlyCodesOrNestedGroupsAreRejected() {
        assertThrows(IllegalArgumentException.class, () -> new PermissionRequirement(PermissionMode.ALL,
                List.of("order:read", "Order:read")));
        assertThrows(IllegalArgumentException.class, () -> new PermissionRequirement(PermissionMode.ALL,
                List.of("order:read", "order:read")));
        var conjunction = PermissionRequirement.allOf(List.of(PermissionRequirement.publicAccess()));
        assertThrows(IllegalArgumentException.class, () -> PermissionRequirement.allOf(List.of(conjunction)));
    }
}
