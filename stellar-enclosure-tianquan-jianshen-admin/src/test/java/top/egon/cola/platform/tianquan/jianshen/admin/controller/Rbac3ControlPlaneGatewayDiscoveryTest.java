package top.egon.cola.platform.tianquan.jianshen.admin.controller;

import io.swagger.v3.oas.annotations.Operation;
import org.junit.jupiter.api.Test;
import org.springframework.boot.security.oauth2.server.resource.autoconfigure.OAuth2ResourceServerAutoConfiguration;
import org.springframework.boot.security.autoconfigure.SecurityAutoConfiguration;
import org.springframework.boot.webmvc.test.autoconfigure.WebMvcTest;
import org.springframework.test.context.bean.override.mockito.MockitoBean;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.web.servlet.mvc.method.annotation.RequestMappingHandlerMapping;
import top.egon.cola.platform.tianquan.jianshen.admin.shared.domain.DatabaseClock;
import top.egon.cola.platform.tianquan.jianshen.admin.authorization.policy.service.ConstraintFacade;
import top.egon.cola.platform.tianquan.jianshen.admin.iam.role.service.RoleFacade;

import java.util.Objects;
import java.util.Set;
import java.util.stream.Collectors;

import top.egon.cola.platform.tianquan.jianshen.admin.authorization.resource.controller.ApplicationResourceController;
import top.egon.cola.platform.tianquan.jianshen.admin.authorization.resource.service.GlobalResourceCatalogService;
import top.egon.cola.platform.tianquan.jianshen.admin.iam.role.controller.RoleController;
import top.egon.cola.platform.tianquan.jianshen.admin.authorization.policy.controller.ConstraintController;

@WebMvcTest(
        properties = {"egon.cola.component.tianshu.enabled=false", "egon.cola.component.tianshu.registry.enabled=false",
                "egon.cola.component.yuheng.reporting.enabled=false", "egon.cola.platform.tianquan.jianshen.enabled=false",
                "egon.cola.platform.tianquan.shoubing.enabled=false"},
        controllers = {
                ApplicationResourceController.class,
                RoleController.class,
                ConstraintController.class,
                top.egon.cola.platform.tianquan.jianshen.admin.authorization.grant.rolepermission.controller.RolePermissionGrantController.class
        },
        excludeAutoConfiguration = {
                SecurityAutoConfiguration.class,
                OAuth2ResourceServerAutoConfiguration.class
        })
class Rbac3ControlPlaneGatewayDiscoveryTest {

    @Autowired
    private RequestMappingHandlerMapping handlerMappings;

    @MockitoBean
    private RoleFacade roleFacade;

    @MockitoBean
    private ConstraintFacade constraintFacade;

    @MockitoBean
    private GlobalResourceCatalogService globalResourceCatalogService;

    @MockitoBean
    private DatabaseClock databaseClock;

    @MockitoBean
    private top.egon.cola.platform.tianquan.jianshen.admin.authorization.grant.rolepermission.service.RolePermissionGrantService rolePermissions;

    @MockitoBean
    private top.egon.cola.platform.tianquan.jianshen.admin.registration.catalog.domain.convertor.PermissionCatalogJson catalogJson;

    @MockitoBean
    private top.egon.cola.platform.tianquan.jianshen.starter.field.PermissionFieldBindingGuard fieldWrites;

    @Test
    void openApiAnnotationsExposeAllResourceRoleAndTypedConstraintOperations() {
        org.assertj.core.api.Assertions.assertThat(operationIds(ApplicationResourceController.class))
                .contains("tianquan-jianshen-application-list-v1", "tianquan-jianshen-application-resource-list-v1");
        org.assertj.core.api.Assertions.assertThat(operationIds(RoleController.class))
                .contains("tianquan-jianshen-role-create-v1", "tianquan-jianshen-role-inheritance-add-v1");
        org.assertj.core.api.Assertions.assertThat(operationIds(ConstraintController.class))
                .contains(
                        "tianquan-jianshen-sod-set-create-v1",
                        "tianquan-jianshen-data-rule-create-v1",
                        "tianquan-jianshen-operation-sod-create-v1")
                .doesNotContain("tianquan-jianshen-field-rule-create-v1", "tianquan-jianshen-field-rule-update-v1");
        org.assertj.core.api.Assertions.assertThat(operationIds(top.egon.cola.platform.tianquan.jianshen.admin.authorization.grant.rolepermission.controller.RolePermissionGrantController.class))
                .contains("tianquan-jianshen-role-permissions-read-v1", "tianquan-jianshen-role-permissions-replace-v1");
    }

    private Set<String> operationIds(Class<?> controllerType) {
        return handlerMappings.getHandlerMethods().values().stream()
                .filter(handler -> controllerType.equals(handler.getBeanType()))
                .map(handler -> handler.getMethod().getAnnotation(Operation.class))
                .filter(Objects::nonNull)
                .map(Operation::operationId)
                .collect(Collectors.toSet());
    }
}
