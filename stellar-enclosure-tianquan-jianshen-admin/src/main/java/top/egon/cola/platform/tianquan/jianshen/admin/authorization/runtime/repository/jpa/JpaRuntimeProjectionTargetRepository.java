package top.egon.cola.platform.tianquan.jianshen.admin.authorization.runtime.repository.jpa;

import jakarta.persistence.EntityManager;
import org.springframework.stereotype.Repository;
import org.springframework.transaction.annotation.Transactional;
import top.egon.cola.platform.tianquan.jianshen.admin.authorization.runtime.repository.RuntimeProjectionTargetRepository;
import top.egon.cola.platform.tianquan.jianshen.admin.iam.user.domain.enums.UserStatusEnum;
import top.egon.cola.platform.tianquan.jianshen.admin.iam.user.domain.po.UserPO;

import java.util.List;
import java.util.Objects;
import java.util.Optional;

/** Keyset-paged projection targets, including inactive memberships that need invalidation. */
@Repository
public class JpaRuntimeProjectionTargetRepository implements RuntimeProjectionTargetRepository {

    private final EntityManager entityManager;

    public JpaRuntimeProjectionTargetRepository(EntityManager entityManager) {
        this.entityManager = Objects.requireNonNull(entityManager, "entityManager");
    }

    @Override
    @Transactional(readOnly = true)
    public List<ProjectionTarget> page(String tenantId, long afterUserId, int limit) {
        if (afterUserId < 0L || limit < 1 || limit > 200) {
            throw new IllegalArgumentException("invalid runtime projection page");
        }
        return entityManager.createQuery("""
                        select u from UserEntity u
                         where u.tenantId = :tenantId and u.id > :afterUserId
                         order by u.id
                        """, UserPO.class)
                .setParameter("tenantId", Long.valueOf(tenantId))
                .setParameter("afterUserId", afterUserId)
                .setMaxResults(limit)
                .getResultList().stream().map(this::target).toList();
    }

    @Override
    @Transactional(readOnly = true)
    public Optional<ProjectionTarget> find(String tenantId, String userId) {
        return entityManager.createQuery("""
                        select u from UserEntity u
                         where u.tenantId = :tenantId and u.id = :userId
                        """, UserPO.class)
                .setParameter("tenantId", Long.valueOf(tenantId))
                .setParameter("userId", Long.valueOf(userId))
                .getResultStream().findFirst().map(this::target);
    }

    @Override
    @Transactional(propagation = org.springframework.transaction.annotation.Propagation.MANDATORY)
    public void beginTenantProjection(String tenantId) {
        int changed = entityManager.createNativeQuery("""
                update rbac3_tenant_authorization_state set version = version where tenant_id = :tenant
                """).setParameter("tenant", Long.valueOf(tenantId)).executeUpdate();
        if (changed != 1) throw new org.springframework.dao.TransientDataAccessResourceException("authorization tenant is not yet visible");
    }

    @Override
    @Transactional(propagation = org.springframework.transaction.annotation.Propagation.MANDATORY)
    public void requirePage(String tenantId, long afterUserId, List<ProjectionTarget> page) {
        if (afterUserId < 0 || page == null || page.isEmpty() || page.size() > 200) {
            throw new IllegalArgumentException("invalid runtime projection page");
        }
        List<Long> ids = page.stream().map(value -> Long.valueOf(value.userId())).toList();
        long previous = afterUserId;
        for (Long id : ids) {
            if (id <= previous) throw new IllegalArgumentException("runtime projection page is not ordered");
            previous = id;
        }
        StringBuilder sql = new StringBuilder("""
                update rbac3_tenant_authorization_state set version = version
                 where tenant_id = :tenant
                   and (select count(*) from rbac3_user u where u.tenant_id = :tenant
                        and u.id > :after and u.id <= :last) = :count
                """);
        for (int index = 0; index < ids.size(); index++) {
            sql.append(" and exists (select 1 from rbac3_user u where u.tenant_id = :tenant and u.id = :id")
                    .append(index).append(')');
        }
        var query = entityManager.createNativeQuery(sql.toString()).setParameter("tenant", Long.valueOf(tenantId))
                .setParameter("after", afterUserId).setParameter("last", previous).setParameter("count", ids.size());
        for (int index = 0; index < ids.size(); index++) query.setParameter("id" + index, ids.get(index));
        if (query.executeUpdate() != 1) {
            throw new org.springframework.dao.OptimisticLockingFailureException("tenant projection page is incomplete or stale");
        }
    }

    @Override
    @Transactional(propagation = org.springframework.transaction.annotation.Propagation.MANDATORY)
    public void requireExhausted(String tenantId, long afterUserId) {
        if (afterUserId < 0) throw new IllegalArgumentException("invalid runtime projection cursor");
        int changed = entityManager.createNativeQuery("""
                update rbac3_tenant_authorization_state set version = version
                 where tenant_id = :tenant
                   and not exists (select 1 from rbac3_user u where u.tenant_id = :tenant and u.id > :after)
                """).setParameter("tenant", Long.valueOf(tenantId)).setParameter("after", afterUserId).executeUpdate();
        if (changed != 1) throw new org.springframework.dao.OptimisticLockingFailureException("tenant projection tail is not yet visible");
    }

    private ProjectionTarget target(UserPO user) {
        return new ProjectionTarget(user.getId().toString(), user.getIdentitySub(),
                user.getAuthVersion(), user.getStatus() == UserStatusEnum.ACTIVE);
    }
}
