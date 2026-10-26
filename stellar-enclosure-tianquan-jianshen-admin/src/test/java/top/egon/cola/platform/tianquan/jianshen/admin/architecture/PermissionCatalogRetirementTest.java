package top.egon.cola.platform.tianquan.jianshen.admin.architecture;

import org.junit.jupiter.api.Test;
import top.egon.cola.platform.tianquan.jianshen.admin.Rbac3AdminApplication;
import top.egon.cola.platform.tianquan.jianshen.admin.authorization.policy.controller.ConstraintController;
import top.egon.cola.platform.tianquan.jianshen.admin.authorization.resource.controller.ApplicationResourceController;

import java.util.Arrays;
import java.util.List;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

/** Retired authority paths cannot silently revive through classpath scanning or CLI fallback. */
class PermissionCatalogRetirementTest {
    private static final String ROOT = "top.egon.cola.platform.tianquan.jianshen.admin.";

    @Test
    void retiredCommandsFailBeforeAnyApplicationContextCanStart() {
        for (String command : List.of("register-application-catalog", "replace-role-field-rules")) {
            assertThatThrownBy(() -> Rbac3AdminApplication.main(new String[]{command}))
                    .isInstanceOf(IllegalArgumentException.class).hasMessageContaining("retired");
        }
    }

    @Test
    void oldAuthorityControllersAndAutomaticGrantHooksAreAbsentFromTheArtifact() {
        for (String name : List.of("registration.ci.controller.CiResourceRegistrationController",
                "authorization.grant.roleresource.controller.RoleResourceGrantController",
                "authorization.permission.controller.ResourcePermissionMappingController",
                "authorization.permission.controller.PermissionController",
                "authorization.resource.controller.cli.Rbac3ApplicationCatalogRegistrationCli",
                "bootstrap.service.Rbac3DevelopmentBootstrap", "bootstrap.service.Rbac3DevelopmentResourceBootstrap")) {
            assertThatThrownBy(() -> Class.forName(ROOT + name, false, getClass().getClassLoader()))
                    .isInstanceOf(ClassNotFoundException.class);
        }
    }

    @Test
    void manualFieldWritersAreRetiredWhileDataRulesAndRoleConstraintsRemain() {
        assertThat(Arrays.stream(ApplicationResourceController.class.getDeclaredMethods()).map(method -> method.getName()))
                .doesNotContain("createField", "changeFieldStatus");
        assertThat(Arrays.stream(ConstraintController.class.getDeclaredMethods()).map(method -> method.getName()))
                .doesNotContain("createFieldRule", "updateFieldRule")
                .contains("dataRules", "createDataRule", "updateDataRule", "sodSets", "cardinality", "prerequisites");
    }
}
