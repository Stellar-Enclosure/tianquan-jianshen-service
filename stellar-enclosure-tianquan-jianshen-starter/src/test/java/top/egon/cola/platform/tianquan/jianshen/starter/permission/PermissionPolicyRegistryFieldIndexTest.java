package top.egon.cola.platform.tianquan.jianshen.starter.permission;

import org.junit.jupiter.api.Test;
import top.egon.cola.platform.tianquan.jianshen.contract.permission.ResourceAccess;
import java.util.List;
import java.util.Set;
import static org.junit.jupiter.api.Assertions.*;
import static top.egon.cola.platform.tianquan.jianshen.starter.permission.PermissionRuntimeFixture.*;

class PermissionPolicyRegistryFieldIndexTest {
    static class Base { public String name; }
    static class Child extends Base { public String note; }

    @Test void inheritedFieldsStayImmutableAndIsolatedBetweenManifestsUnderConcurrentUse() {
        var first = registry(manifest(List.of(field(Base.class, "name", ResourceAccess.PUBLIC, null),
                field(Child.class, "note", ResourceAccess.PUBLIC, null))));
        var second = registry(manifest(List.of(field(Base.class, "name", ResourceAccess.PUBLIC, null))));
        java.util.stream.IntStream.range(0, 100).parallel().forEach(ignored -> {
            assertEquals(Set.of("name", "note"), first.fields(Child.class).keySet());
            assertEquals(Set.of("name"), second.fields(Child.class).keySet());
        });
        assertThrows(UnsupportedOperationException.class, () -> first.fields(Child.class).clear());
    }
}
