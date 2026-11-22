package top.egon.cola.platform.tianquan.jianshen.admin.controller;

import org.junit.jupiter.api.AfterEach;
import org.springdoc.core.configuration.SpringDocConfiguration;
import org.springdoc.core.configuration.SpringDocSpecPropertiesConfiguration;
import org.springdoc.core.properties.SpringDocConfigProperties;
import org.springdoc.webmvc.core.configuration.MultipleOpenApiSupportConfiguration;
import org.springdoc.webmvc.core.configuration.SpringDocWebMvcConfiguration;
import org.springframework.boot.context.properties.EnableConfigurationProperties;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.context.annotation.Import;
import org.springframework.mock.env.MockEnvironment;
import org.springframework.mock.web.MockServletContext;
import org.springframework.web.context.support.AnnotationConfigWebApplicationContext;
import org.springframework.web.servlet.config.annotation.EnableWebMvc;
import static org.hamcrest.Matchers.endsWith;
import static org.hamcrest.Matchers.hasItems;
import static org.hamcrest.Matchers.startsWith;
import org.junit.jupiter.api.Test;
import top.egon.cola.platform.tianquan.jianshen.admin.iam.role.domain.vo.RoleEditDetailVO;
import top.egon.cola.platform.tianquan.jianshen.admin.shared.tenant.domain.TenantContext;
import top.egon.cola.platform.tianquan.jianshen.core.rule.Rbac3RuleViolation;
import static org.mockito.Mockito.when;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.header;
import org.springframework.test.web.servlet.setup.MockMvcBuilders;
import top.egon.cola.platform.tianquan.jianshen.admin.iam.role.controller.RoleController;
import top.egon.cola.platform.tianquan.jianshen.admin.iam.role.service.RoleFacade;
import top.egon.cola.platform.tianquan.jianshen.admin.shared.controller.Rbac3ApiExceptionHandler;
import top.egon.cola.platform.tianquan.jianshen.admin.shared.domain.DatabaseClock;

import static org.mockito.Mockito.mock;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.jsonPath;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

class RoleEditDetailContractTest {

    private static final String DETAIL = "/api/tianquan-jianshen/v1/iam/roles/{roleId}";

    @Test
    void generatedIamDocumentPublishesTheOperationAndRoleSchema() throws Exception {
        try (var context = new AnnotationConfigWebApplicationContext()) {
            context.setServletContext(new MockServletContext());
            context.setEnvironment(new MockEnvironment()
                    .withProperty("springdoc.api-docs.enabled", "true")
                    .withProperty("springdoc.api-docs.version", "OPENAPI_3_1")
                    .withProperty("springdoc.group-configs[0].group", "iam")
                    .withProperty("springdoc.group-configs[0].paths-to-match[0]", "/api/tianquan-jianshen/v1/iam/**")
                    .withProperty("springdoc.packages-to-scan[0]", RoleController.class.getPackageName()));
            context.register(DocumentConfiguration.class);
            context.refresh();

            String operation = "$.paths['" + DETAIL + "'].get";
            MockMvcBuilders.webAppContextSetup(context).build()
                    .perform(get("/v3/api-docs/iam"))
                    .andExpect(status().isOk())
                    .andExpect(jsonPath("$.openapi").value(startsWith("3.1.")))
                    .andExpect(jsonPath(operation + ".operationId").value("tianquan-jianshen-role-edit-detail-v1"))
                    .andExpect(jsonPath(operation + ".security[0].bearerAuth").isArray())
                    .andExpect(jsonPath("$.components.securitySchemes.bearerAuth.scheme").value("bearer"))
                    .andExpect(jsonPath(operation + ".responses['200'].headers['Cache-Control']").exists())
                    .andExpect(jsonPath(operation + ".responses['401'].headers['WWW-Authenticate']").exists())
                    .andExpect(jsonPath(operation + ".responses['200'].content['application/json'].schema.$ref")
                            .value(endsWith("/ResultRecordRoleEditDetailVO")))
                    .andExpect(jsonPath(operation + ".responses['400'].content['application/json'].schema.$ref")
                            .value(endsWith("/ResultRecord")))
                    .andExpect(jsonPath(operation + ".responses['401'].content['application/json'].schema.$ref")
                            .value(endsWith("/RoleEditSecurityErrorVO")))
                    .andExpect(jsonPath(operation + ".responses['403'].content['application/json'].schema.anyOf").isArray())
                    .andExpect(jsonPath(operation + ".responses['404'].content['application/json'].schema.$ref")
                            .value(endsWith("/ResultRecord")))
                    .andExpect(jsonPath(operation + ".responses['503'].content['application/json'].schema.anyOf").isArray())
                    .andExpect(jsonPath(operation + ".parameters[0].name").value("roleId"))
                    .andExpect(jsonPath(operation + ".parameters[0].required").value(true))
                    .andExpect(jsonPath("$.components.schemas.RoleEditDetailVO.properties.landingRouteId.type",
                            hasItems("string", "null")))
                    .andExpect(jsonPath("$.components.schemas.RoleEditDetailVO.properties.maximumAssignmentDays.type",
                            hasItems("integer", "null")))
                    .andExpect(jsonPath("$.components.schemas.RoleEditDetailVO.properties.version.format").value("int64"));
        }
    }

    @Configuration(proxyBeanMethods = false)
    @EnableWebMvc
    @EnableConfigurationProperties(SpringDocConfigProperties.class)
    @Import({SpringDocConfiguration.class, SpringDocWebMvcConfiguration.class,
            SpringDocSpecPropertiesConfiguration.class, MultipleOpenApiSupportConfiguration.class})
    static class DocumentConfiguration {
        @Bean("roleController")
        RoleController roleController() {
            return new RoleController(mock(RoleFacade.class), mock(DatabaseClock.class));
        }
    }

    @AfterEach
    void clearTenant() {
        TenantContext.clear();
    }

    @Test
    void returnsOriginalValuesAndPreservesExplicitNull() throws Exception {
        var facade = mock(RoleFacade.class);
        TenantContext.set(new TenantContext("10", "11", true));
        when(facade.roleEditDetail("10", 3801L)).thenReturn(
                new RoleEditDetailVO("3801", "20", "仓库运营", "ACTIVE", null, 10, null, 7));

        MockMvcBuilders.standaloneSetup(new RoleController(facade, mock(DatabaseClock.class))).build()
                .perform(get(DETAIL, "3801"))
                .andExpect(status().isOk())
                .andExpect(header().string("Cache-Control", "no-store"))
                .andExpect(jsonPath("$.data.roleId").value("3801"))
                .andExpect(jsonPath("$.data.applicationId").value("20"))
                .andExpect(jsonPath("$.data.roleName").value("仓库运营"))
                .andExpect(jsonPath("$.data.status").value("ACTIVE"))
                .andExpect(jsonPath("$.data.landingRouteId").hasJsonPath())
                .andExpect(jsonPath("$.data.landingRouteId").value(org.hamcrest.Matchers.nullValue()))
                .andExpect(jsonPath("$.data.landingPriority").value(10))
                .andExpect(jsonPath("$.data.maximumAssignmentDays").hasJsonPath())
                .andExpect(jsonPath("$.data.maximumAssignmentDays").value(org.hamcrest.Matchers.nullValue()))
                .andExpect(jsonPath("$.data.version").value(7));
    }

    @Test
    void inaccessibleRoleUsesTheExistingNotFoundEnvelope() throws Exception {
        var facade = mock(RoleFacade.class);
        TenantContext.set(new TenantContext("10", "10", false));
        when(facade.roleEditDetail("10", 3801L)).thenThrow(new Rbac3RuleViolation("RESOURCE_NOT_FOUND"));
        var mvc = MockMvcBuilders.standaloneSetup(new RoleController(facade, mock(DatabaseClock.class)))
                .setControllerAdvice(new Rbac3ApiExceptionHandler())
                .build();

        mvc.perform(get(DETAIL, "3801"))
                .andExpect(status().isNotFound())
                .andExpect(jsonPath("$.status").value("RESOURCE_NOT_FOUND"));
    }

    @Test
    void invalidRoleIdUsesTheExistingRequestInvalidEnvelope() throws Exception {
        var controller = new RoleController(mock(RoleFacade.class), mock(DatabaseClock.class));
        var mvc = MockMvcBuilders.standaloneSetup(controller)
                .setControllerAdvice(new Rbac3ApiExceptionHandler())
                .build();

        for (String roleId : new String[] {"invalid", "01", "0", "9223372036854775808"}) {
            mvc.perform(get(DETAIL, roleId))
                    .andExpect(status().isBadRequest())
                    .andExpect(jsonPath("$.status").value("REQUEST_INVALID"));
        }
    }
}
