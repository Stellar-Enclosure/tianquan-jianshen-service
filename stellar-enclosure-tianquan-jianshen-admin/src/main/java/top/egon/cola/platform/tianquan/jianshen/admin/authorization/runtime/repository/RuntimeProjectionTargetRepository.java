package top.egon.cola.platform.tianquan.jianshen.admin.authorization.runtime.repository;

import java.util.List;
import java.util.Optional;

/** Reads existing tenant memberships for runtime repair without creating identity data. */
public interface RuntimeProjectionTargetRepository {

    List<ProjectionTarget> page(String tenantId, long afterUserId, int limit);

    Optional<ProjectionTarget> find(String tenantId, String userId);

    void beginTenantProjection(String tenantId);

    void requirePage(String tenantId, long afterUserId, List<ProjectionTarget> page);

    void requireExhausted(String tenantId, long afterUserId);

    record ProjectionTarget(String userId, String identitySub, long authVersion, boolean active) {
    }
}
