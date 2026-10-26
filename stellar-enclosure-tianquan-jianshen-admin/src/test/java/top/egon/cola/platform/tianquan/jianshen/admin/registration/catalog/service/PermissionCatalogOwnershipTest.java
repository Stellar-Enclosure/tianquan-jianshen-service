package top.egon.cola.platform.tianquan.jianshen.admin.registration.catalog.service;

import jakarta.persistence.EntityManager;
import org.junit.jupiter.api.Test;
import top.egon.cola.platform.tianquan.jianshen.admin.registration.catalog.domain.PermissionCatalogCaller;
import top.egon.cola.platform.tianquan.jianshen.admin.registration.catalog.repository.PermissionCatalogDefinitionRepository;
import top.egon.cola.platform.tianquan.jianshen.contract.permission.CatalogScope;
import top.egon.cola.platform.tianquan.jianshen.core.rule.Rbac3RuleViolation;

import java.util.Map;

import static org.junit.jupiter.api.Assertions.assertDoesNotThrow;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.verifyNoInteractions;

class PermissionCatalogOwnershipTest {

    private final EntityManager entityManager = mock(EntityManager.class);
    private final PermissionCatalogDefinitionRepository repository = new PermissionCatalogDefinitionRepository(entityManager);

    @Test
    void trustedCrossApplicationPublisherStillRequiresTenantAndCapability() {
        var caller = PermissionCatalogFixture.caller();
        assertDoesNotThrow(() -> caller.require(PermissionCatalogFixture.SCOPE, PermissionCatalogCaller.Capability.REGISTER, PermissionCatalogFixture.NOW));
        assertThrows(Rbac3RuleViolation.class, () -> caller.require(new CatalogScope("1", "11", "biz", "app", "default", "test"),
                PermissionCatalogCaller.Capability.REGISTER, PermissionCatalogFixture.NOW));
        assertThrows(Rbac3RuleViolation.class, () -> caller.require(PermissionCatalogFixture.SCOPE, PermissionCatalogCaller.Capability.ACTIVATE, PermissionCatalogFixture.NOW));
        assertThrows(Rbac3RuleViolation.class, () -> caller.require(PermissionCatalogFixture.SCOPE, PermissionCatalogCaller.Capability.REGISTER, PermissionCatalogFixture.NOW.plusSeconds(3600)));
    }

    @Test
    void validOwnerCanKeepDisabledIdentityButCannotEnableIt() {
        var identity = new PermissionCatalogDefinitionRepository.Identity("101", "app.read", "api", "DISABLED", "API");
        assertDoesNotThrow(() -> repository.validate(PermissionCatalogFixture.owner(0), PermissionCatalogFixture.manifest(),
                new PermissionCatalogDefinitionRepository.Identities(Map.of("app.read", identity), Map.of(), Map.of())));
        assertEquals("DISABLED", identity.state());
        verifyNoInteractions(entityManager);
    }

    @Test
    void otherOwnerRetirementAndCaseOnlyRebindingAreConflicts() {
        for (var identity : java.util.List.of(
                new PermissionCatalogDefinitionRepository.Identity("101", "app.read", "other", "ACTIVE", "API"),
                new PermissionCatalogDefinitionRepository.Identity("101", "app.read", "api", "RETIRED", "API"),
                new PermissionCatalogDefinitionRepository.Identity("101", "APP.READ", "api", "ACTIVE", "API"))) {
            assertEquals("RESOURCE_MANIFEST_CONFLICT", assertThrows(Rbac3RuleViolation.class, () -> repository.validate(
                    PermissionCatalogFixture.owner(0), PermissionCatalogFixture.manifest(),
                    new PermissionCatalogDefinitionRepository.Identities(Map.of(identity.key(), identity), Map.of(), Map.of()))).reasonCode());
        }
        verifyNoInteractions(entityManager);
    }

    @Test
    void meaningCannotChangeEvenWhenPermissionIsNotInTheActiveManifest() {
        var identity = new PermissionCatalogDefinitionRepository.Identity("201", "app.read", "api", "ACTIVE", "Delete app records");
        assertEquals("RESOURCE_MANIFEST_CONFLICT", assertThrows(Rbac3RuleViolation.class, () -> repository.validate(
                PermissionCatalogFixture.owner(0), PermissionCatalogFixture.manifest(),
                new PermissionCatalogDefinitionRepository.Identities(Map.of(), Map.of("app.read", identity), Map.of()))).reasonCode());
    }

    @Test
    void missingSourceMessageReferenceIsRejected() {
        var value = PermissionCatalogFixture.manifest();
        var missing = new top.egon.cola.platform.tianquan.jianshen.contract.permission.PermissionManifest(value.schemaVersion(), value.application(),
                value.producer(), value.artifact(), value.permissionDefinitions(), value.permissionReferences(), value.resources(), value.resourceReferences(), java.util.List.of());
        assertEquals("RESOURCE_MANIFEST_INVALID", assertThrows(Rbac3RuleViolation.class, () -> repository.validate(
                PermissionCatalogFixture.owner(0), missing, new PermissionCatalogDefinitionRepository.Identities(Map.of(), Map.of(), Map.of()))).reasonCode());
    }
}
