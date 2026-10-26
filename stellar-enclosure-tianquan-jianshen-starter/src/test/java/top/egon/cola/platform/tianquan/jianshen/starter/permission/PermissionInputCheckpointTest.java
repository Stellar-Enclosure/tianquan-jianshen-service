package top.egon.cola.platform.tianquan.jianshen.starter.permission;

import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.Test;
import top.egon.cola.platform.tianquan.jianshen.contract.authorization.ServicePolicySnapshot;
import top.egon.cola.platform.tianquan.jianshen.starter.client.Rbac3AuthorizationClient;
import java.util.List;
import java.util.Set;
import static org.junit.jupiter.api.Assertions.*;
import static top.egon.cola.platform.tianquan.jianshen.starter.permission.PermissionRuntimeFixture.*;

class PermissionInputCheckpointTest {
    static class Input { public String name; }
    @AfterEach void reset() { org.springframework.web.context.request.RequestContextHolder.resetRequestAttributes(); }

    @Test void userInputIsBoundToTheCheckedPermissionSetAndContextNeverLeaks() {
        var manifest=manifest(List.of(field(Input.class,"name",top.egon.cola.platform.tianquan.jianshen.contract.permission.ResourceAccess.PUBLIC,null)));
        var earlier=snapshot(manifest,Set.of("field:write"));
        var revoked=snapshot(manifest,Set.of());
        try(var context=new PermissionExecutionContext("shop.api.write")) {
            PermissionExecutionContext.rememberInput(earlier);
            PermissionExecutionContext.verifyInput("shop.api.write",earlier);
            assertThrows(Rbac3AuthorizationClient.AuthorizationUnavailableException.class,
                    ()->PermissionExecutionContext.verifyInput("shop.api.write",revoked));
        }
        try(var next=new PermissionExecutionContext("shop.api.write")) {
            assertDoesNotThrow(()->PermissionExecutionContext.verifyInput("shop.api.write",revoked));
        }
    }

    @Test void serviceInputChecksCannotCombineTwoPolicyVersionsOrReuseANestedBoundary() {
        var user=snapshot(manifest(List.of(field(Input.class,"name",top.egon.cola.platform.tianquan.jianshen.contract.permission.ResourceAccess.PUBLIC,null))),Set.of());
        var before=new ServicePolicySnapshot(SCOPE,"1","3",user.policyBinding(),Set.of("shop.api.write"),NOW.plusSeconds(30));
        var after=new ServicePolicySnapshot(SCOPE,"1","4",user.policyBinding(),Set.of("shop.api.write"),NOW.plusSeconds(30));
        try(var context=new PermissionExecutionContext("shop.api.write")) {
            PermissionExecutionContext.rememberInput(before);
            try(var nested=new PermissionExecutionContext("shop.api.other")) {
                PermissionExecutionContext.rememberInput(after);
            }
            assertEquals("shop.api.write",PermissionExecutionContext.currentApiKey());
            assertThrows(Rbac3AuthorizationClient.AuthorizationUnavailableException.class,
                    ()->PermissionExecutionContext.rememberInput(after));
        }
    }
}
