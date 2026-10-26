package top.egon.cola.platform.tianquan.jianshen.admin.authorization.resource;

import org.junit.jupiter.api.Test;
import org.springframework.web.bind.annotation.GetMapping;
import top.egon.cola.platform.tianquan.jianshen.admin.authorization.resource.controller.ApplicationResourceController;

import static org.assertj.core.api.Assertions.assertThat;

class FieldCrudControllerTest {

    @Test
    void exposesHistoricalFieldReadsWithoutManualDefinitionWriters() {
        assertThat(java.util.Arrays.stream(ApplicationResourceController.class.getDeclaredMethods())
                .filter(method -> method.getName().equals("fields")
                        || method.getName().equals("resourceFields")))
                .allMatch(method -> method.isAnnotationPresent(GetMapping.class));
        assertThat(java.util.Arrays.stream(ApplicationResourceController.class.getDeclaredMethods()).map(method -> method.getName()))
                .doesNotContain("createField", "changeFieldStatus");
    }
}
