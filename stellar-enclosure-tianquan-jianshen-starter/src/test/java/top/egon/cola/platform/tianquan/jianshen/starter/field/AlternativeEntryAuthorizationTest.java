package top.egon.cola.platform.tianquan.jianshen.starter.field;

import com.fasterxml.jackson.databind.ObjectMapper;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.Test;
import org.springframework.mock.web.MockHttpServletRequest;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.web.context.request.RequestContextHolder;
import org.springframework.web.context.request.ServletRequestAttributes;
import top.egon.cola.component.common.desensitize.strategy.SensitiveStrategyRegistry;
import top.egon.cola.platform.tianquan.jianshen.contract.permission.*;
import top.egon.cola.platform.tianquan.jianshen.starter.cache.SingleFlightSnapshotLoader;
import top.egon.cola.platform.tianquan.jianshen.starter.client.Rbac3AuthorizationClient;
import top.egon.cola.platform.tianquan.jianshen.starter.permission.*;
import top.egon.cola.platform.tianquan.jianshen.starter.security.CurrentRbac3User;
import top.egon.cola.platform.tianquan.shoubing.starter.security.VerifiedUserTokenCarrier;
import java.util.*;
import static org.junit.jupiter.api.Assertions.*;
import static top.egon.cola.platform.tianquan.jianshen.starter.permission.PermissionRuntimeFixture.*;

class AlternativeEntryAuthorizationTest {
    public static class Row { public String email="ada@example.com"; }
    private final PermissionManifest manifest = manifest(List.of(
            new PermissionManifest.ResourceDefinition("shop.api.export", ResourceType.API,
                    Map.of("methods",List.of("GET"),"paths",List.of("/export")),ResourceAccess.PROTECTED,all("order:read"),null,
                    List.of(PermissionManifest.PrincipalType.USER),List.of(),new PermissionManifest.I18nReference("shop","export"),DefinitionLifecycle.ACTIVE),
            field(Row.class,"email",ResourceAccess.PROTECTED,new PermissionManifest.FieldPolicy(PermissionManifest.JsonFieldType.STRING,
                    all("field:plain"), all("field:masked"), all("field:write"),"EMAIL"))));
    @AfterEach void clear() { SecurityContextHolder.clearContext(); RequestContextHolder.resetRequestAttributes(); }
    private PermissionExecutionGuard guard(Set<String> codes) {
        authenticate(manifest,codes); var request=new MockHttpServletRequest(); VerifiedUserTokenCarrier.set(request,"original-proof");
        RequestContextHolder.setRequestAttributes(new ServletRequestAttributes(request));
        Rbac3AuthorizationClient client=(system,user)->snapshot(manifest,codes);
        return new PermissionExecutionGuard(registry(manifest),new CurrentRbac3User(),new SingleFlightSnapshotLoader(client,"shop",CLOCK));
    }
    @Test void csvExportUsesAuthorizedProjectionAndLeavesSourceUnchanged() {
        var guard=guard(Set.of("order:read","field:masked")); var registry=registry(manifest); var users=new CurrentRbac3User();
        var mapper=new ObjectMapper().registerModule(new Rbac3FieldJacksonModule(users,SensitiveStrategyRegistry.defaults(),registry,
                new PermissionFieldBindingGuard(registry,users)));
        Row row=new Row();
        var tree=new PermissionOutputProjection(guard,mapper).project("shop.api.export",row);
        String csv="email\n"+tree.path("email").asText()+"\n";
        assertFalse(csv.contains("ada@example.com")); assertEquals("ada@example.com",row.email);
    }
    @Test void directRpcAndBatchAdaptersMustAuthorizeBeforeCallingTheWriter() {
        var guard=guard(Set.of("order:read")); var fields=new PermissionFieldBindingGuard(registry(manifest),new CurrentRbac3User());
        int[] writes={0};
        assertThrows(org.springframework.security.authorization.AuthorizationDeniedException.class,()->{
            guard.require("shop.api.export");
            for(int i=0;i<2;i++) fields.require(Row.class,new SubmittedFieldSet(Set.of("email")),Set.of("email"));
            writes[0]+=2;
        });
        assertEquals(0,writes[0]);
        SecurityContextHolder.clearContext();
        assertThrows(org.springframework.security.authentication.AuthenticationCredentialsNotFoundException.class,()->guard.require("shop.api.export"));
    }
}
