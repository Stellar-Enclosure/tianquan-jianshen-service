package top.egon.cola.platform.tianquan.jianshen.admin.authorization.runtime.catalog;

import com.fasterxml.jackson.databind.ObjectMapper;
import jakarta.persistence.EntityManager;
import jakarta.persistence.Query;
import org.junit.jupiter.api.Test;
import top.egon.cola.platform.tianquan.jianshen.admin.authorization.runtime.activation.repository.*;
import top.egon.cola.platform.tianquan.jianshen.admin.authorization.runtime.activation.domain.vo.*;
import top.egon.cola.platform.tianquan.jianshen.admin.iam.role.service.RoleEligibilityService;
import top.egon.cola.platform.tianquan.jianshen.core.activation.*;
import top.egon.cola.platform.tianquan.jianshen.core.hierarchy.*;
import top.egon.cola.platform.tianquan.jianshen.core.rule.Rbac3RuleViolation;
import java.time.Duration;
import java.util.*;
import static org.junit.jupiter.api.Assertions.*;
import static org.mockito.ArgumentMatchers.*;
import static org.mockito.Mockito.*;
import static top.egon.cola.platform.tianquan.jianshen.admin.authorization.runtime.catalog.RuntimeProofBindingTest.*;

class PermissionRuntimeSnapshotRepositoryTest {
    @Test void exactScopePermissionCharactersBecomeTheHeadWithBoundedExpiry() {
        Fixture fixture=new Fixture();
        var snapshot=fixture.repository.current(new PermissionRuntimeProofService.VerifiedRequest(binding(),ISSUER,user()));
        assertEquals(Set.of("order:read"),snapshot.permissions());
        assertEquals(SCOPE,snapshot.permissionSnapshot().catalogScope());
        assertEquals(List.of("50"),snapshot.permissionSnapshot().activeRoleContext().effectiveRoleIds());
        assertEquals(NOW.plusSeconds(30),snapshot.expiresAt());
        assertEquals(2,fixture.writes.size());
        assertEquals("20",fixture.writes.getFirst().get("tenant").toString());
        assertEquals("30",fixture.writes.getFirst().get("subject"));
        assertTrue(fixture.sql.stream().anyMatch(sql->sql.contains("g.catalog_scope_id = :scope")&&sql.contains("g.role_id in (:roles)")));
        assertTrue(fixture.sql.indexOf(fixture.sql.stream().filter(sql->sql.contains("for share of s")).findFirst().orElseThrow())
                <fixture.sql.indexOf(fixture.sql.stream().filter(sql->sql.contains("policy_version from rbac3_tenant")).findFirst().orElseThrow()));
    }
    @Test void staleOrForeignDeploymentCannotWriteAnySnapshotOrHead() {
        Fixture fixture=new Fixture(); fixture.artifact="f".repeat(64);
        assertEquals("AUTH_DEPLOYMENT_BINDING_MISMATCH",assertThrows(Rbac3RuleViolation.class,()->fixture.repository.current(
                new PermissionRuntimeProofService.VerifiedRequest(binding(),ISSUER,user()))).reasonCode());
        assertTrue(fixture.writes.isEmpty());
    }
    @Test void databaseVersionDriftRejectsRatherThanCombiningOldFactsAndNewVersion() {
        Fixture fixture=new Fixture();fixture.policy=4L;
        assertEquals("AUTH_RUNTIME_VERSION_CONFLICT",assertThrows(Rbac3RuleViolation.class,()->fixture.repository.current(
                new PermissionRuntimeProofService.VerifiedRequest(binding(),ISSUER,user()))).reasonCode());
        assertTrue(fixture.writes.isEmpty());
    }
    @Test void laterRolePolicyVersionDoesNotRequireAnotherCatalogActivation() {
        Fixture fixture = new Fixture(); fixture.policy = 4L;
        var previous = fixture.facts.load("20", "60", NOW);
        when(fixture.facts.load(anyString(), anyString(), any())).thenReturn(new ActivationFactsVO(previous.tenantId(), previous.userId(),
                previous.hierarchy(), previous.assignments(), previous.dsdSets(), previous.authorizationFacts(), 2L, 4L,
                previous.directorySnapshotVersion(), previous.applications(), previous.roleDisplayNames()));
        var snapshot = fixture.repository.current(new PermissionRuntimeProofService.VerifiedRequest(binding(), ISSUER, user()));
        assertEquals("1", snapshot.permissionSnapshot().catalogVersion());
        assertEquals("4", snapshot.permissionSnapshot().policyVersion());
        assertEquals(Set.of("order:read"), snapshot.permissions());
    }

    @Test void qualificationExpiryOnlyConstrainsTheHistoricalActivationPoint() {
        Fixture fixture = new Fixture();
        fixture.activatedAt = NOW.minusSeconds(3600);
        fixture.qualifiedAt = NOW.minusSeconds(3601);
        fixture.qualificationExpiresAt = NOW.minusSeconds(2700);
        assertEquals("1", fixture.repository.policy(binding(), NOW.plusSeconds(100)).catalogVersion());
        assertEquals(Set.of("order:read"), fixture.repository.current(
                new PermissionRuntimeProofService.VerifiedRequest(binding(), ISSUER, user())).permissions());
        fixture.qualifiedAt = fixture.activatedAt.plusSeconds(1);
        assertEquals("AUTH_DEPLOYMENT_BINDING_MISMATCH", assertThrows(Rbac3RuleViolation.class,
                () -> fixture.repository.policy(binding(), NOW.plusSeconds(100))).reasonCode());
        fixture.qualifiedAt = fixture.activatedAt.minusSeconds(1);
        fixture.qualificationExpiresAt = fixture.activatedAt;
        assertEquals("AUTH_DEPLOYMENT_BINDING_MISMATCH", assertThrows(Rbac3RuleViolation.class,
                () -> fixture.repository.policy(binding(), NOW.plusSeconds(100))).reasonCode());
    }

    @Test void noActiveRolesIsAValidEmptyViewWithoutAnInitialPermissionGrant() {
        Fixture fixture=new Fixture();
        when(fixture.active.current(anyString(),anyString(),anyString(),any())).thenReturn(new CurrentStateVO(Map.of(),2,3,"none",true));
        var result=fixture.repository.current(new PermissionRuntimeProofService.VerifiedRequest(binding(),ISSUER,user()));
        assertTrue(result.permissions().isEmpty()); assertTrue(result.permissionSnapshot().activeRoleContext().rootRoleIds().isEmpty());
    }
    private static class Fixture {
        final EntityManager manager=mock(EntityManager.class);
        final RoleActivationFactRepository facts=mock(RoleActivationFactRepository.class);
        final ActivationTransaction active=mock(ActivationTransaction.class);
        final RoleEligibilityService eligibility=mock(RoleEligibilityService.class);
        final List<String> sql=new ArrayList<>();
        final List<Map<String,Object>> writes=new ArrayList<>();
        final PermissionRuntimeSnapshotRepository repository;
        String artifact="a".repeat(64); long policy=3;
        java.time.Instant activatedAt=NOW.minusSeconds(5), qualifiedAt=NOW.minusSeconds(10), qualificationExpiresAt=NOW.plusSeconds(900);
        Fixture() {
            var hierarchy=new RoleHierarchy(List.of(new RoleNode("50","40","reader",true,RoleNode.RiskLevel.LOW,false,null,0)),List.of());
            var rules=new AuthorizationRuleFacts(List.of(),List.of(),List.of(),List.of(),List.of(),List.of(),
                    List.of(new AuthorizationRuleFacts.PermissionGrantBinding("10","40","50","order:read")));
            when(facts.load(anyString(),anyString(),any())).thenReturn(new ActivationFactsVO("20","60",hierarchy,
                    List.of(new EligibleAssignmentFact("70","60","50",EligibleAssignmentFact.Status.ACTIVE,NOW.minusSeconds(100),null)),
                    List.of(),rules,2,3,"directory:1",Map.of("40",new ApplicationFactVO("40","shop","Shop")),Map.of("50","Reader")));
            when(active.current(anyString(),anyString(),anyString(),any())).thenReturn(new CurrentStateVO(Map.of("40",Set.of("50")),2,3,"ok",false));
            when(eligibility.isEffectiveForProjection(anyString(),anyString(),anyString(),any())).thenReturn(true);
            when(manager.createNativeQuery(anyString())).thenAnswer(call->{
                String text=call.getArgument(0); sql.add(text);
                Query query=mock(Query.class);Map<String,Object> parameters=new LinkedHashMap<>();
                when(query.setParameter(anyString(),any())).thenAnswer(parameter->{parameters.put(parameter.getArgument(0),parameter.getArgument(1));return query;});
                when(query.getResultList()).thenAnswer(ignored->rows(text));
                when(query.executeUpdate()).thenAnswer(ignored->{writes.add(Map.copyOf(parameters));return 1;});
                return query;
            });
            repository=new PermissionRuntimeSnapshotRepository(manager,new ObjectMapper().findAndRegisterModules(),facts,active,eligibility,
                    ()->NOW,new PermissionRuntimeProperties(Duration.ofSeconds(30),List.of(binding())),()->100L);
        }
        List<?> rows(String text) {
            if(text.contains("for share of s")) return List.<Object[]>of(new Object[]{10L,20L,"commerce","shop","default","test",40L});
            if(text.contains("policy_version from rbac3_tenant")) return List.of(policy);
            if(text.contains("select id, auth_version from rbac3_user")) return List.<Object[]>of(new Object[]{60L,2L});
            if(text.contains("select a.activation_version")) return List.<Object[]>of(new Object[]{1L,3L,1L,"c".repeat(64),"b".repeat(64),artifact,activatedAt,qualifiedAt,qualificationExpiresAt});
            if(text.contains("select distinct p.permission_code")) return List.of("order:read");
            if(text.contains("select rv.registration_key")) return List.of("shop.api.read");
            return List.of();
        }
    }
}
