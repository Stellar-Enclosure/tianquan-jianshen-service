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
        var denied = assertThrows(Rbac3RuleViolation.class,()->fixture.repository.current(
                new PermissionRuntimeProofService.VerifiedRequest(binding(),ISSUER,user())));
        assertEquals("AUTH_DEPLOYMENT_BINDING_MISMATCH", denied.reasonCode());
        var evidence = assertInstanceOf(top.egon.cola.platform.tianquan.jianshen.starter.permission.RuntimeBindingMismatchEvidence.class, denied.getCause());
        assertEquals(List.of("ARTIFACT_DIGEST_MISMATCH"), evidence.failedChecks());
        assertEquals("f".repeat(64), evidence.selected().artifactDigest());
        assertEquals("a".repeat(64), evidence.configuredProducer().get("artifactDigest"));
        assertTrue(fixture.writes.isEmpty());
    }
    @Test void databaseVersionDriftRejectsRatherThanCombiningOldFactsAndNewVersion() {
        Fixture fixture=new Fixture();fixture.policy=4L;
        assertEquals("AUTH_RUNTIME_VERSION_CONFLICT",assertThrows(Rbac3RuleViolation.class,()->fixture.repository.current(
                new PermissionRuntimeProofService.VerifiedRequest(binding(),ISSUER,user()))).reasonCode());
        assertTrue(fixture.writes.isEmpty());
    }
    @Test void localClientKeepsBindingEvidenceAsAnInternalCauseWithoutChangingThePublicReason() {
        Fixture fixture = new Fixture(); fixture.artifact = "f".repeat(64);
        var proof = new PermissionRuntimeProofService.VerifiedRequest(binding(), ISSUER, user());
        var failure = assertThrows(Rbac3RuleViolation.class, () -> fixture.repository.current(proof));
        var proofs = mock(PermissionRuntimeProofService.class);
        var snapshots = mock(PermissionRuntimeSnapshotRepository.class);
        when(proofs.local(user(), "verified-proof")).thenReturn(proof);
        when(snapshots.current(proof)).thenThrow(failure);
        var client = new PermissionRuntimeConfiguration().localCatalogAuthorizationClient(proofs, snapshots);
        var denied = assertThrows(top.egon.cola.platform.tianquan.jianshen.starter.client.Rbac3AuthorizationClient.AuthorizationDeniedException.class,
                () -> client.fetch("shop", user(), "verified-proof"));
        assertEquals("AUTH_DEPLOYMENT_BINDING_MISMATCH", denied.getMessage());
        assertSame(failure, denied.getCause());
    }
    @Test void verifiedLocalUserReceivesAnIdForAnActualPreSnapshotBindingFailure() throws Exception {
        Fixture fixture = new Fixture(); fixture.artifact = "f".repeat(64);
        var verified = new PermissionRuntimeProofService.VerifiedRequest(binding(), ISSUER, user());
        var proofs = mock(PermissionRuntimeProofService.class);
        when(proofs.local(user(), "verified-proof")).thenReturn(verified);
        var client = new PermissionRuntimeConfiguration().localCatalogAuthorizationClient(proofs, fixture.repository);
        var loader = new top.egon.cola.platform.tianquan.jianshen.starter.cache.AuthorizationSnapshotLoader(client, "shop",
                java.time.Clock.fixed(NOW, java.time.ZoneOffset.UTC));
        var events = new ArrayList<top.egon.cola.platform.tianquan.jianshen.starter.permission.PermissionDenialDiagnostic>();
        var audit = new top.egon.cola.platform.tianquan.jianshen.starter.permission.PermissionDenialAudit(() -> null, events::add,
                java.time.Clock.fixed(NOW, java.time.ZoneOffset.UTC));
        var filter = new top.egon.cola.platform.tianquan.jianshen.starter.security.Rbac3BearerAuthenticationFilter(loader, new ObjectMapper(), audit);
        var observations = mock(top.egon.cola.platform.tianquan.shoubing.starter.security.IdpObservedVerificationComponent.class);
        var tokenProof = new top.egon.cola.platform.tianquan.shoubing.starter.security.domain.TokenAuditProofBO(
                ISSUER, RESOURCE, "a".repeat(64), null, "b".repeat(64));
        when(observations.enabled()).thenReturn(true);
        when(observations.authorizationDenied(eq(tokenProof), anyString())).thenReturn(true);
        var request = new org.springframework.mock.web.MockHttpServletRequest("GET", "/api/shop");
        var response = new org.springframework.mock.web.MockHttpServletResponse();
        top.egon.cola.platform.tianquan.shoubing.starter.security.VerifiedUserTokenCarrier.set(request, "verified-proof");
        org.springframework.web.context.request.RequestContextHolder.setRequestAttributes(
                new org.springframework.web.context.request.ServletRequestAttributes(request, response));
        var authentication = new top.egon.cola.platform.tianquan.shoubing.starter.security.IdpAuthenticationToken(user(), List.of(), ISSUER);
        authentication.setDetails(tokenProof);
        org.springframework.security.core.context.SecurityContextHolder.getContext().setAuthentication(authentication);
        try {
            new top.egon.cola.platform.tianquan.shoubing.starter.security.IdpSecurityObservationFilter(observations,
                    new top.egon.cola.platform.tianquan.shoubing.starter.security.IdpEndpointAuthenticationPolicy())
                    .doFilter(request, response, (incoming, outgoing) -> filter.doFilter(incoming, outgoing, new org.springframework.mock.web.MockFilterChain()));
            assertEquals(403, response.getStatus());
            assertEquals(1, events.size());
            assertEquals(response.getHeader("X-Permission-Decision-Id"), events.getFirst().decisionId());
            assertEquals("RUNTIME_BINDING", events.getFirst().decisionKind());
            assertEquals("unavailable", events.getFirst().authVersion());
            assertEquals("f".repeat(64), events.getFirst().binding().artifactDigest());
            assertFalse(events.getFirst().resolvePermissionSources());
            assertTrue(fixture.writes.isEmpty());
        } finally {
            org.springframework.web.context.request.RequestContextHolder.resetRequestAttributes();
            org.springframework.security.core.context.SecurityContextHolder.clearContext();
        }
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
    @Test void executionViewUsesTheActivatedProducerAndRejectsCorruptPolicyBytes() {
        Fixture fixture = new Fixture();
        var proof = new ExecutionGrantAuthorizationService.VerifiedExecution(binding(), ISSUER, "30", NOW.plusSeconds(60), "shop.api.read");
        var view = fixture.repository.currentExecution(proof);
        assertEquals("shop.api.read", view.resource().key());
        assertEquals(Set.of("order:read"), view.snapshot().permissions());
        assertTrue(fixture.sql.stream().anyMatch(sql -> sql.contains("ap.producer_id = :producer")
                && sql.contains("ap.producer_version = :version") && sql.contains("rv.registration_key = :key")));
        fixture.definitionDigest = "f".repeat(64);
        assertEquals("AUTH_RUNTIME_CHECKSUM_MISMATCH", assertThrows(Rbac3RuleViolation.class,
                () -> fixture.repository.currentExecution(proof)).reasonCode());
    }
    @Test void serviceExecutionViewReadsCurrentPolicyAndResourceWithoutCreatingAUserSnapshot() {
        Fixture fixture = new Fixture();
        var view = fixture.repository.currentServiceExecution(binding(), NOW.plusSeconds(60), "shop.api.read");
        assertEquals("shop.api.read", view.resource().key());
        assertEquals(SCOPE, view.snapshot().catalogScope());
        assertEquals(Set.of("shop.api.read"), view.snapshot().resourceKeys());
        assertEquals(NOW.plusSeconds(30), view.snapshot().expiresAt());
        assertTrue(fixture.writes.isEmpty());
        assertTrue(fixture.sql.stream().noneMatch(sql -> sql.contains("select id, auth_version from rbac3_user")));
        assertTrue(fixture.sql.stream().noneMatch(sql -> sql.contains("for share")));
        fixture.definitionDigest = "f".repeat(64);
        assertEquals("AUTH_RUNTIME_CHECKSUM_MISMATCH", assertThrows(Rbac3RuleViolation.class,
                () -> fixture.repository.currentServiceExecution(binding(), NOW.plusSeconds(60), "shop.api.read")).reasonCode());
    }
    @Test void executionViewActuallyEntersTheSpringTransactionProxy() {
        Fixture fixture = new Fixture();
        try (var context = new org.springframework.context.annotation.AnnotationConfigApplicationContext()) {
            context.register(TransactionConfiguration.class);
            context.registerBean(PermissionRuntimeSnapshotRepository.class, () -> fixture.repository);
            context.refresh();
            var repository = context.getBean(PermissionRuntimeSnapshotRepository.class);
            assertTrue(org.springframework.aop.support.AopUtils.isAopProxy(repository));
            repository.currentExecution(new ExecutionGrantAuthorizationService.VerifiedExecution(
                    binding(), ISSUER, "30", NOW.plusSeconds(60), "shop.api.read"));
            assertTrue(fixture.transactionObserved);
            fixture.transactionObserved = false;
            repository.currentServiceExecution(binding(), NOW.plusSeconds(60), "shop.api.read");
            assertTrue(fixture.transactionObserved);
            assertEquals(java.sql.Connection.TRANSACTION_REPEATABLE_READ, fixture.transactionIsolation);
        }
    }

    @org.springframework.context.annotation.Configuration(proxyBeanMethods = false)
    @org.springframework.transaction.annotation.EnableTransactionManagement(proxyTargetClass = true)
    static class TransactionConfiguration {
        @org.springframework.context.annotation.Bean
        org.springframework.transaction.PlatformTransactionManager transactionManager() {
            return new org.springframework.transaction.support.AbstractPlatformTransactionManager() {
                @Override protected Object doGetTransaction() { return new Object(); }
                @Override protected void doBegin(Object transaction, org.springframework.transaction.TransactionDefinition definition) { }
                @Override protected void doCommit(org.springframework.transaction.support.DefaultTransactionStatus status) { }
                @Override protected void doRollback(org.springframework.transaction.support.DefaultTransactionStatus status) { }
            };
        }
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
        String definitionJson, definitionDigest;
        boolean transactionObserved;
        Integer transactionIsolation;
        java.time.Instant activatedAt=NOW.minusSeconds(5), qualifiedAt=NOW.minusSeconds(10), qualificationExpiresAt=NOW.plusSeconds(900);
        Fixture() {
            var resource = new top.egon.cola.platform.tianquan.jianshen.contract.permission.PermissionManifest.ResourceDefinition(
                    "shop.api.read", top.egon.cola.platform.tianquan.jianshen.contract.permission.ResourceType.API,
                    Map.of("methods", List.of("POST"), "paths", List.of("/shop")),
                    top.egon.cola.platform.tianquan.jianshen.contract.permission.ResourceAccess.PROTECTED,
                    new top.egon.cola.platform.tianquan.jianshen.contract.permission.PermissionRequirement(
                            top.egon.cola.platform.tianquan.jianshen.contract.permission.PermissionMode.ALL, List.of("order:read")),
                    null, List.of(top.egon.cola.platform.tianquan.jianshen.contract.permission.PermissionManifest.PrincipalType.USER),
                    List.of(), new top.egon.cola.platform.tianquan.jianshen.contract.permission.PermissionManifest.I18nReference("shop", "read"),
                    top.egon.cola.platform.tianquan.jianshen.contract.permission.DefinitionLifecycle.ACTIVE);
            var definition = new top.egon.cola.platform.tianquan.jianshen.contract.permission.PermissionManifestCanonicalizer().resourceMap(resource);
            definitionJson = top.egon.cola.platform.tianquan.jianshen.contract.permission.CanonicalJson.write(definition);
            definitionDigest = top.egon.cola.platform.tianquan.jianshen.contract.permission.CanonicalJson.digest(definition);
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
            transactionObserved |= org.springframework.transaction.support.TransactionSynchronizationManager.isActualTransactionActive();
            transactionIsolation = org.springframework.transaction.support.TransactionSynchronizationManager.getCurrentTransactionIsolationLevel();
            if(text.contains("from rbac3_catalog_scope s join rbac3_application a")) return List.<Object[]>of(new Object[]{10L,20L,"commerce","shop","default","test",40L});
            if(text.contains("policy_version from rbac3_tenant")) return List.of(policy);
            if(text.contains("select id, auth_version from rbac3_user")) return List.<Object[]>of(new Object[]{60L,2L});
            if(text.contains("select a.activation_version")) return List.<Object[]>of(new Object[]{1L,3L,1L,"c".repeat(64),"b".repeat(64),artifact,activatedAt,qualifiedAt,qualificationExpiresAt});
            if(text.contains("select distinct p.permission_code")) return List.of("order:read");
            if(text.contains("select rv.registration_key")) return List.of("shop.api.read");
            if(text.contains("select cast(rv.definition_json")) return List.<Object[]>of(new Object[]{definitionJson, definitionDigest});
            return List.of();
        }
    }
}
