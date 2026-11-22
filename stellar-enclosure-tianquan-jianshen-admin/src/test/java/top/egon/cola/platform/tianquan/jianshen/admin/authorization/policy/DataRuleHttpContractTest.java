package top.egon.cola.platform.tianquan.jianshen.admin.authorization.policy;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.datatype.jsr310.JavaTimeModule;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.springframework.http.MediaType;
import org.springframework.http.converter.json.MappingJackson2HttpMessageConverter;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.test.web.servlet.MockMvc;
import org.springframework.test.web.servlet.setup.MockMvcBuilders;
import top.egon.cola.platform.tianquan.jianshen.admin.authorization.policy.controller.ConstraintController;
import top.egon.cola.platform.tianquan.jianshen.admin.authorization.policy.domain.vo.MutationResultVO;
import top.egon.cola.platform.tianquan.jianshen.admin.authorization.policy.service.ConstraintFacade;
import top.egon.cola.platform.tianquan.jianshen.admin.registration.catalog.domain.convertor.PermissionCatalogJson;
import top.egon.cola.platform.tianquan.jianshen.admin.shared.controller.Rbac3ApiExceptionHandler;
import top.egon.cola.platform.tianquan.jianshen.contract.permission.CatalogScope;
import top.egon.cola.platform.tianquan.jianshen.starter.field.StrictFieldRequestBodyAdvice;
import top.egon.cola.platform.tianquan.jianshen.starter.field.StrictSubmittedFieldBinder;
import top.egon.cola.platform.tianquan.jianshen.starter.security.Rbac3UserDetails;

import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;

import static org.mockito.ArgumentMatchers.*;
import static org.mockito.Mockito.*;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.post;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.put;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

/** Uses real MVC binding and the shared strict JSON codec; authentication itself is covered by host tests. */
class DataRuleHttpContractTest {
    private static final String PATH = "/api/tianquan-jianshen/v1/iam/policies/data-rules";
    private static final CatalogScope TARGET = new CatalogScope("1", "10", "biz", "app", "space", "test");
    private final top.egon.cola.platform.tianquan.jianshen.starter.field.PermissionFieldBindingGuard fieldWrites = mock(top.egon.cola.platform.tianquan.jianshen.starter.field.PermissionFieldBindingGuard.class);
    private final ConstraintFacade facade = mock(ConstraintFacade.class);
    private final Rbac3UserDetails actor = mock(Rbac3UserDetails.class);
    private final ObjectMapper mapper = new ObjectMapper().registerModule(new JavaTimeModule());
    private final PermissionCatalogJson json = new PermissionCatalogJson(mapper);
    private MockMvc mvc;

    @BeforeEach
    void prepare() {
        var binder = new StrictSubmittedFieldBinder(mapper, fieldWrites);
        mvc = MockMvcBuilders.standaloneSetup(new ConstraintController(facade, json))
                .setControllerAdvice(new Rbac3ApiExceptionHandler(), new StrictFieldRequestBodyAdvice(binder))
                .addFilters(new org.springframework.security.web.access.ExceptionTranslationFilter(
                        (request, response, denied) -> response.sendError(401)))
                .setMessageConverters(new MappingJackson2HttpMessageConverter(mapper)).build();
        when(actor.tenantId()).thenReturn("10");
        when(actor.rbac3UserId()).thenReturn("90");
        SecurityContextHolder.getContext().setAuthentication(UsernamePasswordAuthenticationToken.authenticated(actor, "unused", List.of()));
        when(facade.saveDataRule(any())).thenReturn(new MutationResultVO("100", 1, "propagation", true));
        when(facade.dataRules(TARGET, actor)).thenReturn(List.of());
    }

    @AfterEach
    void cleanup() {
        SecurityContextHolder.clearContext();
    }

    @Test
    void writesCarryTheExactTargetAndDeriveActorFromTheAuthenticatedUser() throws Exception {
        mvc.perform(post(PATH).contentType(MediaType.APPLICATION_JSON).content(json.write(body()))).andExpect(status().isOk());
        verify(facade).saveDataRule(argThat(command -> command.target().equals(TARGET) && command.actor() == actor
                && command.tenantId().equals("10") && command.actorId().equals("90") && command.ruleId() == null));
        mvc.perform(put(PATH + "/100").contentType(MediaType.APPLICATION_JSON).content(json.write(body()))).andExpect(status().isOk());
        verify(facade).saveDataRule(argThat(command -> "100".equals(command.ruleId()) && command.target().equals(TARGET)));
    }

    @Test
    void fieldRejectionPreventsBusinessMutationAndChecksNestedReferences() throws Exception {
        doThrow(new org.springframework.security.authorization.AuthorizationDeniedException("FIELD_ACCESS_DENIED"))
                .when(fieldWrites).require(eq(top.egon.cola.platform.tianquan.jianshen.admin.authorization.policy.domain.vo.RuleReferenceVO.class), any(), anySet());
        var submitted = body();
        submitted.put("references", List.of(Map.of("referenceType", "ORG", "referenceId", "100")));
        mvc.perform(post(PATH).contentType(MediaType.APPLICATION_JSON).content(json.write(submitted)))
                .andExpect(status().isForbidden());
        verify(facade, never()).saveDataRule(any());
        verify(fieldWrites).require(eq(top.egon.cola.platform.tianquan.jianshen.admin.authorization.policy.domain.dto.DataRuleRequestDTO.class),
                argThat(fields -> fields.paths().containsAll(body().keySet())), anySet());
    }

    @Test
    void oldScopeLessBodiesNumericIdsDuplicateKeysAndUnknownFieldsAreRejected() throws Exception {
        var missing = body(); missing.remove("target");
        var numeric = body(); numeric.put("permissionId", 40);
        var unknown = body(); unknown.put("actorId", "attacker");
        var emptyReferences = body(); emptyReferences.put("references", null);
        for (var invalid : List.of(missing, numeric, unknown, emptyReferences)) {
            mvc.perform(post(PATH).contentType(MediaType.APPLICATION_JSON).content(json.write(invalid))).andExpect(status().isBadRequest());
        }
        String duplicate = json.write(body()).replace("\"permissionId\":\"40\"", "\"permissionId\":\"40\",\"permissionId\":\"41\"");
        mvc.perform(post(PATH).contentType(MediaType.APPLICATION_JSON).content(duplicate)).andExpect(status().isBadRequest());
        mvc.perform(post(PATH).contentType(MediaType.APPLICATION_JSON).content(json.write(body()) + " {}"))
                .andExpect(status().isBadRequest());
        verify(facade, never()).saveDataRule(any());
    }

    @Test
    void aTargetTenantAssertionCannotReplaceTheAuthenticatedTenant() throws Exception {
        var invalid = body(); invalid.put("target", new CatalogScope("1", "11", "biz", "app", "space", "test"));
        mvc.perform(post(PATH).contentType(MediaType.APPLICATION_JSON).content(json.write(invalid))).andExpect(status().isForbidden());
        verify(facade, never()).saveDataRule(any());
    }

    @Test
    void readsRequireAllSixSingleValuedTargetParameters() throws Exception {
        mvc.perform(get(PATH)).andExpect(status().isBadRequest());
        mvc.perform(get(PATH).param("catalogScopeId", "1", "2").param("tenantId", "10")
                .param("businessCode", "biz").param("applicationCode", "app").param("namespaceCode", "space")
                .param("environment", "test")).andExpect(status().isBadRequest());
        mvc.perform(get(PATH).param("catalogScopeId", "1").param("tenantId", "10")
                .param("businessCode", "biz").param("applicationCode", "app").param("namespaceCode", "space")
                .param("environment", "test")).andExpect(status().isOk());
        verify(facade).dataRules(TARGET, actor);
    }

    private Map<String, Object> body() {
        var body = new LinkedHashMap<String, Object>();
        body.put("target", TARGET);
        body.put("applicationId", "20");
        body.put("roleId", "30");
        body.put("permissionId", "40");
        body.put("scopeType", "SELF");
        body.put("references", List.of());
        body.put("validFrom", "2026-10-25T00:00:00Z");
        body.put("expectedVersion", 0);
        return body;
    }
}
