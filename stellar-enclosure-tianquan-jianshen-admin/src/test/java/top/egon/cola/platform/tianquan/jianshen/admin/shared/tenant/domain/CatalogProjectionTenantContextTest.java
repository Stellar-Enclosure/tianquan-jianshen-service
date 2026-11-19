package top.egon.cola.platform.tianquan.jianshen.admin.shared.tenant.domain;

import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.NullAndEmptySource;
import org.junit.jupiter.params.provider.ValueSource;

import java.util.concurrent.atomic.AtomicBoolean;
import java.util.concurrent.atomic.AtomicReference;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertSame;
import static org.junit.jupiter.api.Assertions.assertThrows;

class CatalogProjectionTenantContextTest {

    @Test
    void exposesOnlyTheExplicitLexicalTenantAndRestoresAfterReturn() {
        assertNull(CatalogProjectionTenantContext.currentOrNull());

        String result = CatalogProjectionTenantContext.call("17", () -> {
            assertEquals("17", CatalogProjectionTenantContext.currentOrNull());
            return "result";
        });

        assertEquals("result", result);
        assertNull(CatalogProjectionTenantContext.currentOrNull());
        assertEquals(Long.toString(Long.MAX_VALUE), CatalogProjectionTenantContext.call(
                Long.toString(Long.MAX_VALUE), CatalogProjectionTenantContext::currentOrNull));
        assertNull(CatalogProjectionTenantContext.currentOrNull());
    }

    @Test
    void sameTenantMayNestButADifferentTenantNeverRuns() {
        var invoked = new AtomicBoolean();

        CatalogProjectionTenantContext.call("17", () -> {
            assertEquals("17", CatalogProjectionTenantContext.call("17",
                    CatalogProjectionTenantContext::currentOrNull));
            assertEquals("17", CatalogProjectionTenantContext.currentOrNull());
            var failure = assertThrows(IllegalStateException.class,
                    () -> CatalogProjectionTenantContext.call("18", () -> {
                        invoked.set(true);
                        return null;
                    }));
            assertEquals("CATALOG_PROJECTION_TENANT_MISMATCH", failure.getMessage());
            assertEquals("17", CatalogProjectionTenantContext.currentOrNull());
            return null;
        });

        assertFalse(invoked.get());
        assertNull(CatalogProjectionTenantContext.currentOrNull());
    }

    @Test
    void exceptionsPreserveTheirIdentityAndRestoreEveryExitedScope() {
        var expected = new IllegalStateException("projection failed");

        assertSame(expected, assertThrows(IllegalStateException.class,
                () -> CatalogProjectionTenantContext.call("17", () -> {
                    assertSame(expected, assertThrows(IllegalStateException.class,
                            () -> CatalogProjectionTenantContext.call("17", () -> {
                                throw expected;
                            })));
                    assertEquals("17", CatalogProjectionTenantContext.currentOrNull());
                    throw expected;
                })));

        assertNull(CatalogProjectionTenantContext.currentOrNull());
    }

    @ParameterizedTest
    @NullAndEmptySource
    @ValueSource(strings = {"0", "00", "01", "-1", "+1", " 1", "1 ", "1.0", "1e1",
            "9223372036854775808", "99999999999999999999", "١"})
    void rejectsNonCanonicalOrOutOfRangeTenantsBeforeExecuting(String tenantId) {
        var invoked = new AtomicBoolean();

        var failure = assertThrows(IllegalArgumentException.class,
                () -> CatalogProjectionTenantContext.call(tenantId, () -> {
                    invoked.set(true);
                    return null;
                }));

        assertEquals("CATALOG_PROJECTION_TENANT_INVALID", failure.getMessage());
        assertFalse(invoked.get());
        assertNull(CatalogProjectionTenantContext.currentOrNull());
    }

    @Test
    void rejectsMissingActionWithoutCreatingAScope() {
        assertThrows(NullPointerException.class,
                () -> CatalogProjectionTenantContext.call("17", null));
        assertNull(CatalogProjectionTenantContext.currentOrNull());
    }

    @Test
    void unrelatedThreadsCannotInheritProjectionAuthority() throws InterruptedException {
        var observed = new AtomicReference<String>("not executed");

        Thread worker = CatalogProjectionTenantContext.call("17", () -> {
            var thread = Thread.ofPlatform().unstarted(
                    () -> observed.set(CatalogProjectionTenantContext.currentOrNull()));
            thread.start();
            return thread;
        });
        worker.join();

        assertNull(observed.get());
        assertNull(CatalogProjectionTenantContext.currentOrNull());
    }
}
