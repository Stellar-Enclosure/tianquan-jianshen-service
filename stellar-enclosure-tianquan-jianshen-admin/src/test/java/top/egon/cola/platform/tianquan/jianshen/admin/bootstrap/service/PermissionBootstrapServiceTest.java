package top.egon.cola.platform.tianquan.jianshen.admin.bootstrap.service;

import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import top.egon.cola.platform.tianquan.jianshen.admin.audit.service.AuditQueryService;
import top.egon.cola.platform.tianquan.jianshen.admin.authorization.grant.rolepermission.repository.RolePermissionGrantRepository;
import top.egon.cola.platform.tianquan.jianshen.admin.authorization.runtime.repository.AuthorizationEventPublisher;
import top.egon.cola.platform.tianquan.jianshen.admin.authorization.runtime.state.repository.TenantAuthorizationStateRepository;
import top.egon.cola.platform.tianquan.jianshen.admin.bootstrap.controller.cli.PermissionBootstrapCli;
import top.egon.cola.platform.tianquan.jianshen.admin.bootstrap.domain.dto.PermissionAdministratorBootstrapCommandDTO;
import top.egon.cola.platform.tianquan.jianshen.admin.bootstrap.domain.dto.PermissionBootstrapConnectionDTO;
import top.egon.cola.platform.tianquan.jianshen.admin.bootstrap.domain.dto.PermissionCatalogBootstrapCommandDTO;
import top.egon.cola.platform.tianquan.jianshen.admin.bootstrap.domain.vo.PermissionBootstrapReceiptVO;
import top.egon.cola.platform.tianquan.jianshen.admin.bootstrap.repository.PermissionBootstrapRepository;
import top.egon.cola.platform.tianquan.jianshen.admin.registration.catalog.domain.PermissionCatalogCaller;
import top.egon.cola.platform.tianquan.jianshen.admin.registration.catalog.domain.convertor.PermissionCatalogJson;
import top.egon.cola.platform.tianquan.jianshen.admin.registration.catalog.repository.PermissionCatalogScopeRepository;
import top.egon.cola.platform.tianquan.jianshen.admin.shared.domain.DatabaseClock;
import top.egon.cola.platform.tianquan.jianshen.contract.permission.CatalogScope;
import top.egon.cola.platform.tianquan.jianshen.contract.permission.PermissionManifest;
import top.egon.cola.platform.tianquan.jianshen.core.rule.Rbac3RuleViolation;

import java.net.URI;
import java.time.Instant;
import java.util.List;
import java.util.Map;
import java.util.Optional;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;
import static org.mockito.ArgumentMatchers.*;
import static org.mockito.Mockito.*;

class PermissionBootstrapServiceTest {
    private static final Instant NOW = Instant.parse("2026-10-25T00:00:00Z");
    private static final String OPERATION = "00000000-0000-0000-0000-000000000001";
    private static final CatalogScope TARGET = new CatalogScope("1", "10", "xingyuan", "tianquan-jianshen", "default", "test");
    private final PermissionBootstrapRepository repository = mock(PermissionBootstrapRepository.class);
    private final PermissionCatalogScopeRepository scopes = mock(PermissionCatalogScopeRepository.class);
    private final RolePermissionGrantRepository grants = mock(RolePermissionGrantRepository.class);
    private final TenantAuthorizationStateRepository policy = mock(TenantAuthorizationStateRepository.class);
    private final AuthorizationEventPublisher events = mock(AuthorizationEventPublisher.class);
    private final AuditQueryService audit = mock(AuditQueryService.class);
    private final DatabaseClock clock = () -> NOW;
    private final PermissionCatalogJson json = new PermissionCatalogJson(PermissionBootstrapCli.mapper());
    private final PermissionBootstrapService service = new PermissionBootstrapService(repository, scopes, grants, policy, events, audit, clock, json, "a".repeat(64));
    private final PermissionCatalogScopeRepository.ScopeState active = new PermissionCatalogScopeRepository.ScopeState(TARGET, 20, 1, 0);

    @BeforeEach
    void prepare() {
        when(repository.original(anyString(), anyString(), anyString())).thenReturn(Optional.empty());
        when(repository.initializeCatalog(any(), eq(NOW))).thenReturn(Map.of("r-java/grant/digest", "30"));
        when(scopes.lockScope(TARGET)).thenReturn(active);
        when(repository.initializeAdministrator(eq(active), any(), eq(NOW), eq(NOW)))
                .thenReturn(new PermissionBootstrapRepository.Administrator(90, 40, 50, 1));
        when(grants.replace(eq(active), eq(40L), any(), eq(PermissionBootstrapRepository.ACTOR), eq(NOW)))
                .thenReturn(new RolePermissionGrantRepository.Mutation("1", 1, 0));
        when(policy.increment(10L, PermissionBootstrapRepository.ACTOR)).thenReturn(2L);
        when(repository.application(TARGET)).thenReturn(new PermissionBootstrapRepository.ApplicationBinding(20, "biz-public", "app-public"));
        when(repository.producerIds(TARGET)).thenReturn(List.of("r-java"));
    }

    @Test
    void b0OnlyInitializesSourceOwnersAndPersistsAnOriginalReceipt() {
        var command = catalog();
        var receipt = service.catalog(command, false);
        assertThat(receipt.stage()).isEqualTo("B0");
        assertThat(receipt.commandDigest()).isEqualTo(service.digest(command));
        assertThat(receipt.facts()).containsEntry("r-java/grant/digest", "30");
        verifyNoInteractions(scopes, grants, policy, events);
        verify(audit).record(argThat(value -> value.eventType().equals("PERMISSION_CATALOG_BOOTSTRAPPED")
                && value.requestId().equals(OPERATION) && value.afterSnapshot().containsKey("receipt")));
    }

    @Test
    void committedOriginalOutcomeDoesNotReenableChangedOwnersOrRegrantPermissions() {
        var original = service.catalog(catalog(), false);
        clearInvocations(repository, audit);
        when(repository.original("10", OPERATION, service.digest(catalog()))).thenReturn(Optional.of(original));
        assertThat(service.catalog(catalog(), true)).isEqualTo(original);
        verify(repository, never()).initializeCatalog(any(), any());
        verifyNoInteractions(audit, grants, policy, events);
    }

    @Test
    void existingReceiptRequiresTheMatchingCommittedDatabaseAudit() {
        assertThatThrownBy(() -> service.catalog(catalog(), true)).hasMessage("BOOTSTRAP_COMMITTED_RECEIPT_MISSING");
        assertThatThrownBy(() -> service.administrator(administrator("1", true, null), true)).hasMessage("BOOTSTRAP_COMMITTED_RECEIPT_MISSING");
        verify(repository, never()).initializeCatalog(any(), any());
        verify(repository, never()).initializeAdministrator(any(), any(), any(), any());
        verifyNoInteractions(scopes, grants, policy, events, audit);
    }

    @Test
    void unactivatedOrStaleCatalogCannotInitializeAnAdministrator() {
        assertThatThrownBy(() -> service.administrator(administrator("2", true, null), false)).hasMessage("BOOTSTRAP_ACTIVE_REVISION_CONFLICT");
        when(scopes.lockScope(TARGET)).thenReturn(new PermissionCatalogScopeRepository.ScopeState(TARGET, 20, 0, 0));
        assertThatThrownBy(() -> service.administrator(administrator("1", true, null), false)).hasMessage("BOOTSTRAP_ACTIVE_REVISION_CONFLICT");
        verify(repository, never()).initializeAdministrator(any(), any(), any(), any());
        verifyNoInteractions(grants, policy, events, audit);
    }

    @Test
    void incompleteQualificationAndSecondOperationCannotEnlargeTheBootstrapGrant() {
        doThrow(new IllegalStateException("BOOTSTRAP_ACTIVE_QUALIFICATION_MISSING")).when(repository).requireQualifiedActiveCatalog(active);
        assertThatThrownBy(() -> service.administrator(administrator("1", false, null), false))
                .hasMessage("BOOTSTRAP_ACTIVE_QUALIFICATION_MISSING");
        verifyNoInteractions(grants, policy, events, audit);
        doThrow(new IllegalStateException("BOOTSTRAP_ADMIN_ALREADY_INITIALIZED")).when(repository).requireAdministratorNotInitialized(TARGET);
        assertThatThrownBy(() -> service.administrator(administrator("1", false, null), false))
                .hasMessage("BOOTSTRAP_ADMIN_ALREADY_INITIALIZED");
        verify(repository, never()).initializeAdministrator(any(), any(), any(), any());
    }

    @Test
    void b1OriginalReceiptRecoveryDoesNotReapplyAnAssignmentOrActivation() {
        var command = administrator("1", false, null);
        var original = service.administrator(command, false);
        clearInvocations(repository, scopes, policy, grants, events, audit);
        when(repository.original("10", OPERATION, service.digest(command))).thenReturn(Optional.of(original));
        assertThat(service.administrator(command, false)).isEqualTo(original);
        verify(repository).lockTenant("10");
        verify(repository).original("10", OPERATION, service.digest(command));
        verifyNoMoreInteractions(repository);
        verifyNoInteractions(scopes, policy, grants, events, audit);
    }

    @Test
    void inactiveUnknownCodesAndFutureActiveAssignmentsAreRejectedBeforeIdentityWrites() {
        doThrow(new Rbac3RuleViolation("RESOURCE_NOT_FOUND")).when(grants).requireActiveCodes(TARGET, List.of("system:role:read"));
        assertThatThrownBy(() -> service.administrator(administrator("1", true, null), false)).isInstanceOf(Rbac3RuleViolation.class);
        assertThatThrownBy(() -> service.administrator(administrator("1", true, NOW.plusSeconds(60)), false))
                .isInstanceOf(IllegalArgumentException.class);
        verify(repository, never()).initializeAdministrator(any(), any(), any(), any());
        verifyNoInteractions(events, audit);
    }

    @Test
    void b1ValidatesCodesThenWritesTheFiniteGrantVersionsEventAndAuditInOrder() {
        var command = administrator("1", true, null);
        var receipt = service.administrator(command, false);
        assertThat(receipt.stage()).isEqualTo("B1");
        assertThat(receipt.facts()).containsEntry("roleId", "40").containsEntry("activeRole", "true").containsEntry("policyVersion", "2");
        var order = inOrder(scopes, policy, grants, repository, events, audit);
        order.verify(repository).lockTenant("10");
        order.verify(repository).original("10", OPERATION, service.digest(command));
        order.verify(repository).requireAdministratorNotInitialized(TARGET);
        order.verify(scopes).lockScope(TARGET);
        order.verify(repository).requireQualifiedActiveCatalog(active);
        order.verify(policy).requireForUpdate(10L);
        order.verify(grants).requireActiveCodes(TARGET, List.of("system:role:read"));
        order.verify(repository).initializeAdministrator(active, command, NOW, NOW);
        order.verify(grants).replace(eq(active), eq(40L), argThat(value -> value.permissionCodes().equals(command.permissionCodes()) && value.expectedVersion().equals("0")), eq(PermissionBootstrapRepository.ACTOR), eq(NOW));
        order.verify(policy).increment(10L, PermissionBootstrapRepository.ACTOR);
        order.verify(events).enqueue(argThat(value -> value.eventType().equals("ROLE_PERMISSION_CHANGED") && value.safePayload().get("policyVersion").equals("2")));
        order.verify(repository).application(TARGET);
        order.verify(repository).producerIds(TARGET);
        order.verify(audit).record(any());
    }

    @Test
    void eventAndAuditFailuresRemainFailuresOfTheOwningTransaction() throws Exception {
        doThrow(new IllegalStateException("outbox unavailable")).when(events).enqueue(any());
        assertThatThrownBy(() -> service.administrator(administrator("1", true, null), false)).hasMessage("outbox unavailable");
        verifyNoInteractions(audit);
        doReturn("event").when(events).enqueue(any());
        doThrow(new IllegalStateException("audit unavailable")).when(audit).record(any());
        assertThatThrownBy(() -> service.administrator(administrator("1", true, null), false)).hasMessage("audit unavailable");
        var transaction = PermissionBootstrapService.class.getMethod("administrator", PermissionAdministratorBootstrapCommandDTO.class, boolean.class)
                .getAnnotation(org.springframework.transaction.annotation.Transactional.class);
        assertThat(transaction).isNotNull();
        assertThat(transaction.readOnly()).isFalse();
    }

    @Test
    void databaseIdentityAndFiniteInputsArePartOfTheCommandBoundary() throws Exception {
        assertThatThrownBy(() -> new PermissionAdministratorBootstrapCommandDTO(1, OPERATION, "/private/connection.json", TARGET,
                "1", "subject", "BOOTSTRAP_ADMIN", "Initial administrator", List.of("*"), null, null, true)).isInstanceOf(IllegalArgumentException.class);
        var command = json.write(catalog());
        assertThatThrownBy(() -> PermissionBootstrapCli.mapper().readValue(command.substring(0, command.length() - 1)
                + ",\"permissionCodes\":[\"system:role:read\"]}", PermissionCatalogBootstrapCommandDTO.class)).isInstanceOf(Exception.class);
        var first = new PermissionBootstrapConnectionDTO("jdbc:postgresql://db.example/rbac", "rbac", "42", "owner", "owner", "/private/password", 0, "public");
        var second = new PermissionBootstrapConnectionDTO("jdbc:postgresql://db.example/rbac", "rbac", "43", "owner", "owner", "/private/password", 0, "public");
        assertThat(first.bindingDigest()).isNotEqualTo(second.bindingDigest());
    }

    @Test
    void b0AcceptsUnderscorePermissionNamespacesThroughTheStrictCommandParser() throws Exception {
        var encoded = json.write(catalog()).replace("\"system:\"", "\"TIANSHU_\"");
        var command = PermissionBootstrapCli.mapper().readValue(encoded, PermissionCatalogBootstrapCommandDTO.class);

        assertThat(command.producers().getFirst().ownedPermissionPrefixes()).containsExactly("TIANSHU_");
        service.catalog(command, false);
        verify(repository).initializeCatalog(command, NOW);
        verifyNoInteractions(scopes, grants, policy, events);
    }

    @Test
    void b0KeepsExplicitPermissionBoundariesAndRejectsUnderscoreResourceOrMessageBoundaries() throws Exception {
        var encoded = json.write(catalog());
        for (String invalid : List.of(
                encoded.replace("\"system:\"", "\"TIANSHU\""),
                encoded.replace("\"system:\"", "\"TIANSHU*\""),
                encoded.replace("\"tianquan-jianshen.api.\"", "\"tianshu_api_\""),
                encoded.replace("\"permission/\"", "\"permission_\""))) {
            assertThatThrownBy(() -> PermissionBootstrapCli.mapper().readValue(invalid, PermissionCatalogBootstrapCommandDTO.class))
                    .isInstanceOf(com.fasterxml.jackson.databind.JsonMappingException.class)
                    .hasRootCauseInstanceOf(IllegalArgumentException.class);
        }
        verify(repository, never()).initializeCatalog(any(), any());
    }

    private PermissionCatalogBootstrapCommandDTO catalog() {
        var grant = new PermissionCatalogBootstrapCommandDTO.ServiceGrant(URI.create("https://idp.example/tenants/10"), "ci", URI.create("https://rbac.example"),
                List.of(PermissionCatalogCaller.Capability.REGISTER), List.of("refs/heads/main"), false);
        var producer = new PermissionCatalogBootstrapCommandDTO.Producer("r-java", PermissionManifest.ProducerKind.JAVA,
                List.of("tianquan-jianshen.api."), List.of("system:"), List.of("permission/"), List.of("admin"), List.of(grant));
        return new PermissionCatalogBootstrapCommandDTO(1, OPERATION, "/private/connection.json", TARGET, "20", "RBAC", "biz-public", "app-public", List.of(producer));
    }

    private PermissionAdministratorBootstrapCommandDTO administrator(String revision, boolean activeRole, Instant from) {
        return new PermissionAdministratorBootstrapCommandDTO(1, OPERATION, "/private/connection.json", TARGET, revision, "subject", "BOOTSTRAP_ADMIN",
                "Initial administrator", List.of("system:role:read"), from, null, activeRole);
    }
}
