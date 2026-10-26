package top.egon.cola.platform.tianquan.jianshen.admin.authorization.resource.service;

import jakarta.persistence.EntityManager;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.validation.annotation.Validated;
import org.springframework.beans.factory.annotation.Qualifier;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;
import top.egon.cola.platform.tianquan.jianshen.admin.iam.application.domain.vo.ApplicationVO;
import top.egon.cola.platform.tianquan.jianshen.admin.authorization.resource.domain.vo.ArchiveResultVO;
import top.egon.cola.platform.tianquan.jianshen.admin.authorization.resource.domain.vo.ResourceVO;
import top.egon.cola.platform.tianquan.jianshen.admin.authorization.resource.field.domain.vo.FieldDefinitionVO;
import top.egon.cola.platform.tianquan.jianshen.admin.shared.domain.DatabaseClock;

import java.util.List;

/** Global application/resource catalog queries and manual resource lifecycle operations. */
@Service("globalResourceCatalogService")
@Validated
@RequiredArgsConstructor(onConstructor_ = @Autowired)
@Slf4j
public class GlobalResourceCatalogService {

    @Qualifier("jpaSharedEM_entityManagerFactory")
    private final EntityManager entityManager;
    @Qualifier("jpaDatabaseClock")
    private final DatabaseClock clock;

    @Transactional(readOnly = true)
    public List<ApplicationVO> applications() {
        return entityManager.createNativeQuery("""
                        select id, application_code, application_name, status, version
                          from rbac3_application
                         order by display_priority, application_code
                        """)
                .getResultList().stream()
                .map(GlobalResourceCatalogService::application)
                .toList();
    }

    @Transactional(readOnly = true)
    public List<ResourceVO> resources(String applicationId) {
        return entityManager.createNativeQuery("""
                        select id, application_id, resource_type, resource_code,
                               resource_name, parent_resource_id,
                               required_permission_id, status, version
                          from rbac3_resource
                         where application_id = :applicationId
                         order by resource_type, resource_code
                        """)
                .setParameter("applicationId", Long.valueOf(applicationId))
                .getResultList().stream()
                .map(GlobalResourceCatalogService::resource)
                .toList();
    }

    @Transactional
    public ArchiveResultVO archive(
            String resourceId,
            long expectedVersion,
            String actorId) {
        int updated = entityManager.createNativeQuery("""
                        update rbac3_resource
                           set status = 'ARCHIVED', version = version + 1,
                               updated_at = :now, updated_by = :actor
                         where id = :id and version = :version
                        """)
                .setParameter("now", clock.transactionNow())
                .setParameter("actor", actorId)
                .setParameter("id", Long.valueOf(resourceId))
                .setParameter("version", expectedVersion)
                .executeUpdate();
        if (updated != 1) {
            throw new IllegalStateException("resource version conflict or not found");
        }
        return new ArchiveResultVO(resourceId, "ARCHIVED", 0L);
    }

    @Transactional(readOnly = true)
    public List<FieldDefinitionVO> fields(String applicationId, String resourceId) {
        String resourcePredicate = resourceId == null ? "" : " and f.resource_id = :resourceId";
        var query = entityManager.createNativeQuery("""
                        select f.id, f.application_id, f.resource_id, f.field_code,
                               f.json_path, f.data_type, f.sensitivity, f.default_access,
                               f.masking_strategy, f.writable, f.exportable, f.status, f.version
                          from rbac3_field_definition f
                         where f.application_id = :applicationId
                        """ + resourcePredicate + " order by f.field_code")
                .setParameter("applicationId", Long.valueOf(applicationId));
        if (resourceId != null) {
            query.setParameter("resourceId", Long.valueOf(resourceId));
        }
        return ((List<?>) query.getResultList()).stream()
                .map(GlobalResourceCatalogService::field)
                .toList();
    }

    private static ApplicationVO application(Object value) {
        Object[] row = (Object[]) value;
        return new ApplicationVO(
                String.valueOf(row[0]), String.valueOf(row[1]), String.valueOf(row[2]),
                String.valueOf(row[3]), ((Number) row[4]).longValue());
    }

    private static ResourceVO resource(Object value) {
        Object[] row = (Object[]) value;
        return new ResourceVO(
                String.valueOf(row[0]), String.valueOf(row[1]), String.valueOf(row[2]),
                String.valueOf(row[3]), String.valueOf(row[4]),
                row[5] == null ? null : String.valueOf(row[5]),
                row[6] == null ? "UNCONFIGURED" : "CONFIGURED",
                String.valueOf(row[7]), ((Number) row[8]).longValue());
    }

    private static FieldDefinitionVO field(Object value) {
        Object[] row = (Object[]) value;
        return new FieldDefinitionVO(
                String.valueOf(row[0]), String.valueOf(row[1]), String.valueOf(row[2]),
                String.valueOf(row[3]), String.valueOf(row[4]), String.valueOf(row[5]),
                String.valueOf(row[6]), String.valueOf(row[7]),
                row[8] == null ? null : String.valueOf(row[8]),
                Boolean.TRUE.equals(row[9]), Boolean.TRUE.equals(row[10]),
                String.valueOf(row[11]), ((Number) row[12]).longValue());
    }
}
