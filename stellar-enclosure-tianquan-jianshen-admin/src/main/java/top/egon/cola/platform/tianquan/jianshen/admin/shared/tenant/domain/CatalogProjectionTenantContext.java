package top.egon.cola.platform.tianquan.jianshen.admin.shared.tenant.domain;

import java.util.Objects;
import java.util.function.Supplier;

/**
 * Lexically carries an already verified runtime binding's tenant through catalog projection.
 * Callers must establish the binding's authority before entering; this scope never authenticates
 * request data, supplies a default tenant, or changes the caller's security context.
 */
public final class CatalogProjectionTenantContext {

    private static final ScopedValue<String> CURRENT = ScopedValue.newInstance();

    private CatalogProjectionTenantContext() {
    }

    /** Executes a projection within one canonical positive-long tenant, without permitting a nested switch. */
    public static <T> T call(String tenantId, Supplier<T> action) {
        requireTenant(tenantId);
        Objects.requireNonNull(action, "action");
        if (CURRENT.isBound() && !CURRENT.get().equals(tenantId)) {
            throw new IllegalStateException("CATALOG_PROJECTION_TENANT_MISMATCH");
        }
        return ScopedValue.where(CURRENT, tenantId).call(action::get);
    }

    /** Returns the verified projection tenant only while its lexical call is active. */
    public static String currentOrNull() {
        return CURRENT.isBound() ? CURRENT.get() : null;
    }

    private static void requireTenant(String tenantId) {
        if (tenantId == null || !tenantId.matches("[1-9][0-9]{0,18}")) {
            throw new IllegalArgumentException("CATALOG_PROJECTION_TENANT_INVALID");
        }
        try {
            Long.parseLong(tenantId);
        } catch (NumberFormatException invalid) {
            throw new IllegalArgumentException("CATALOG_PROJECTION_TENANT_INVALID");
        }
    }
}
