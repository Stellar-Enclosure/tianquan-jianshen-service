package top.egon.cola.platform.tianquan.jianshen.admin.controller;

import org.junit.jupiter.api.Test;
import io.swagger.v3.core.converter.AnnotatedType;
import io.swagger.v3.core.converter.ModelConverters;
import io.swagger.v3.oas.models.media.Schema;
import top.egon.cola.component.yuheng.openapi.annotation.EgonApiCatalog;
import top.egon.cola.platform.tianquan.jianshen.admin.audit.controller.AuditController;
import top.egon.cola.platform.tianquan.jianshen.admin.authorization.grant.business.controller.UserBusinessAccessController;
import top.egon.cola.platform.tianquan.jianshen.admin.authorization.grant.userrole.controller.AssignmentController;
import top.egon.cola.platform.tianquan.jianshen.admin.authorization.policy.controller.ConstraintController;
import top.egon.cola.platform.tianquan.jianshen.admin.authorization.policy.management.controller.ManagementPolicyController;
import top.egon.cola.platform.tianquan.jianshen.admin.authorization.policy.participation.controller.ParticipationController;
import top.egon.cola.platform.tianquan.jianshen.admin.authorization.resource.controller.ApplicationResourceController;
import top.egon.cola.platform.tianquan.jianshen.admin.authorization.runtime.activation.controller.RoleActivationController;
import top.egon.cola.platform.tianquan.jianshen.admin.authorization.runtime.controller.RuntimeController;
import top.egon.cola.platform.tianquan.jianshen.admin.authorization.runtime.decision.controller.InternalAuthorizationController;
import top.egon.cola.platform.tianquan.jianshen.admin.authorization.runtime.decision.controller.Rbac3AboutController;
import top.egon.cola.platform.tianquan.jianshen.admin.authorization.simulation.controller.AuthorizationSimulationController;
import top.egon.cola.platform.tianquan.jianshen.admin.iam.application.controller.ApplicationController;
import top.egon.cola.platform.tianquan.jianshen.admin.iam.business.controller.BusinessCatalogController;
import top.egon.cola.platform.tianquan.jianshen.admin.iam.organization.controller.DirectoryController;
import top.egon.cola.platform.tianquan.jianshen.admin.iam.organization.controller.OrganizationController;
import top.egon.cola.platform.tianquan.jianshen.admin.iam.organization.controller.UserOrganizationAssignmentController;
import top.egon.cola.platform.tianquan.jianshen.admin.iam.position.controller.PositionController;
import top.egon.cola.platform.tianquan.jianshen.admin.iam.position.controller.UserPositionAssignmentController;
import top.egon.cola.platform.tianquan.jianshen.admin.iam.role.controller.RoleController;
import top.egon.cola.platform.tianquan.jianshen.admin.iam.user.controller.UserController;
import top.egon.cola.platform.tianquan.jianshen.admin.iam.user.controller.UserDirectoryController;

import top.egon.cola.platform.tianquan.jianshen.admin.authorization.catalog.controller.CatalogGovernanceController;
import top.egon.cola.platform.tianquan.jianshen.admin.authorization.grant.rolepermission.controller.RolePermissionGrantController;
import top.egon.cola.platform.tianquan.jianshen.admin.authorization.grant.rolepermission.domain.vo.RolePermissionGrantViewVO;
import top.egon.cola.platform.tianquan.jianshen.admin.authorization.grant.rolepermission.domain.dto.ReplaceRolePermissionsRequestDTO;
import top.egon.cola.platform.tianquan.jianshen.admin.registration.catalog.controller.PermissionManifestController;
import top.egon.cola.platform.tianquan.jianshen.admin.registration.catalog.controller.PermissionCatalogActivationController;

import java.util.List;

import static org.assertj.core.api.Assertions.assertThat;

class Rbac3OpenApiGroupContractTest {

    private static final String IAM_GROUP = "iam";

    private static final List<Class<?>> PUBLISHED_IAM_CONTROLLERS = List.of(
            AuditController.class,
            UserBusinessAccessController.class,
            AssignmentController.class,
            ConstraintController.class,
            ManagementPolicyController.class,
            ApplicationResourceController.class,
            RoleActivationController.class,
            RuntimeController.class,
            Rbac3AboutController.class,
            AuthorizationSimulationController.class,
            ApplicationController.class,
            BusinessCatalogController.class,
            DirectoryController.class,
            OrganizationController.class,
            UserOrganizationAssignmentController.class,
            PositionController.class,
            UserPositionAssignmentController.class,
            RoleController.class,
            UserController.class,
            UserDirectoryController.class,
            CatalogGovernanceController.class,
            RolePermissionGrantController.class,
            PermissionManifestController.class,
            PermissionCatalogActivationController.class
    );

    @Test
    void allPublishedRbac3AdminControllersUseTheIamGroup() {
        assertThat(PUBLISHED_IAM_CONTROLLERS).allSatisfy(controller -> {
            EgonApiCatalog catalog = controller.getAnnotation(EgonApiCatalog.class);
            assertThat(catalog)
                    .as("catalog for %s", controller.getSimpleName())
                    .isNotNull();
            assertThat(catalog.interfaceGroupCode()).isEqualTo(IAM_GROUP);
        });
    }

    @Test
    void internalControllersRemainOutsideThePublishedIamGroup() {
        assertThat(catalog(ParticipationController.class).interfaceGroupCode())
                .isEqualTo("business-participation");
        assertThat(catalog(InternalAuthorizationController.class).interfaceGroupCode())
                .isEqualTo("internal-authorization");
    }

    @Test
    void rolePermissionSchemasExposeTheScopeAndPermissionCodeContract() {
        var view = ModelConverters.getInstance(true).resolveAsResolvedSchema(
                new AnnotatedType(RolePermissionGrantViewVO.class).resolveAsRef(true));
        Schema<?> viewSchema = view.referencedSchemas.get("RolePermissionGrantViewVO");
        assertThat(viewSchema.getProperties()).containsKeys("target", "roleId", "version", "catalogVersion", "permissions");
        assertThat(viewSchema.getProperties()).doesNotContainKeys("nodes", "resourceIds", "roleVersion");
        var request = ModelConverters.getInstance(true).resolveAsResolvedSchema(
                new AnnotatedType(ReplaceRolePermissionsRequestDTO.class).resolveAsRef(true));
        Schema<?> requestSchema = request.referencedSchemas.get("ReplaceRolePermissionsRequestDTO");
        assertThat(requestSchema.getProperties()).containsKeys("target", "expectedVersion", "permissionCodes", "validFrom", "validTo");
        assertThat(requestSchema.getProperties()).doesNotContainKey("resourceIds");
    }

    private EgonApiCatalog catalog(Class<?> controller) {
        return controller.getAnnotation(EgonApiCatalog.class);
    }
}
