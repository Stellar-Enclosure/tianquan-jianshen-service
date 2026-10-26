package top.egon.cola.platform.tianquan.jianshen.admin.registration.catalog.service;

import com.fasterxml.jackson.core.type.TypeReference;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.databind.SerializationFeature;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.condition.EnabledIfSystemProperty;
import org.springframework.security.core.context.SecurityContextHolder;
import top.egon.cola.component.common.core.pojo.ResultRecord;
import top.egon.cola.component.common.desensitize.strategy.SensitiveStrategyRegistry;
import top.egon.cola.platform.tianquan.jianshen.contract.permission.CatalogScope;
import top.egon.cola.platform.tianquan.jianshen.contract.permission.ManifestDigests;
import top.egon.cola.platform.tianquan.jianshen.contract.permission.ManifestRegistrationReceipt;
import top.egon.cola.platform.tianquan.jianshen.contract.permission.PermissionManifest;
import top.egon.cola.platform.tianquan.jianshen.contract.permission.PermissionManifestReader;
import top.egon.cola.platform.tianquan.jianshen.core.registration.PermissionManifestDiff;
import top.egon.cola.platform.tianquan.jianshen.starter.field.PermissionFieldBindingGuard;
import top.egon.cola.platform.tianquan.jianshen.starter.field.PermissionJsonMapperFactory;
import top.egon.cola.platform.tianquan.jianshen.starter.permission.PermissionExecutionGuard;
import top.egon.cola.platform.tianquan.jianshen.starter.permission.PermissionPolicyRegistry;
import top.egon.cola.platform.tianquan.jianshen.starter.permission.PermissionServicePolicyGuard;
import top.egon.cola.platform.tianquan.jianshen.starter.security.CurrentRbac3User;
import top.egon.cola.platform.tianquan.shoubing.contract.ServiceIdentityPrincipal;
import top.egon.cola.platform.tianquan.shoubing.starter.security.IdpAuthenticationToken;

import java.net.URI;
import java.nio.file.Files;
import java.nio.file.Path;
import java.time.Clock;
import java.time.Instant;
import java.time.ZoneOffset;
import java.util.List;
import java.util.Map;
import java.util.Set;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.verifyNoInteractions;

/** Exercises the actual Admin response DTOs against their compiler-produced FIELD definitions. */
@EnabledIfSystemProperty(named = "permission.producer.enabled", matches = "true")
class PermissionBootstrapResponseFieldTest {
    private static final Instant NOW = Instant.parse("2026-10-25T00:00:00Z");
    private static final String REGISTER = "tianquan-jianshen:permission-manifest:register";
    private static final CatalogScope TARGET = new CatalogScope("1", "10", "xingyuan", "tianquan-jianshen", "default", "test");
    private static final ManifestDigests DIGESTS = new ManifestDigests("a".repeat(64), "b".repeat(64), "c".repeat(64));
    private final PermissionServicePolicyGuard policies = mock(PermissionServicePolicyGuard.class);
    private final ObjectMapper plain = new ObjectMapper().findAndRegisterModules().disable(SerializationFeature.WRITE_DATES_AS_TIMESTAMPS);

    @AfterEach
    void clear() { SecurityContextHolder.clearContext(); }

    @Test
    void firstPlanResponseKeepsEveryProtocolFieldWithoutAnActiveRuntimeSnapshot() throws Exception {
        String key = "tianquan-jianshen.api.manifest.plan";
        var registry = registry(key);
        var users = new CurrentRbac3User();
        var fields = new PermissionFieldBindingGuard(registry, users, policies);
        var transport = new PermissionJsonMapperFactory(users, SensitiveStrategyRegistry.defaults(), registry, fields).forTransport(plain);
        var plan = new PermissionManifestPlanService.Result("101", TARGET, "tianquan-jianshen-java", "0", "0", DIGESTS,
                new PermissionManifestDiff.Result(List.of(), false, false, false), NOW.plusSeconds(300));
        service();
        try (var boundary = new PermissionExecutionGuard(registry, users, null, policies).open(key)) {
            var response = plain.readTree(transport.writeValueAsString(ResultRecord.success(plan))).path("data");
            assertThat(response.size()).isEqualTo(8);
            assertThat(response.path("planId").asText()).isEqualTo("101");
            assertThat(response.path("target").path("catalogScopeId").asText()).isEqualTo("1");
            assertThat(response.path("expiresAt").asText()).isEqualTo(NOW.plusSeconds(300).toString());
            verifyNoInteractions(policies);
        }
    }

    @Test
    void registrationAndOriginalOutcomeUseTheSameCompiledProtocolDto() throws Exception {
        var receipt = new ManifestRegistrationReceipt("00000000-0000-0000-0000-000000000001", "101", TARGET,
                "tianquan-jianshen-java", "1", DIGESTS, Map.of(), Map.of(), 0, 0, 0, NOW);
        for (String key : List.of("tianquan-jianshen.api.manifest.register", "tianquan-jianshen.api.manifest.status")) {
            var registry = registry(key);
            var users = new CurrentRbac3User();
            var fields = new PermissionFieldBindingGuard(registry, users, policies);
            var transport = new PermissionJsonMapperFactory(users, SensitiveStrategyRegistry.defaults(), registry, fields).forTransport(plain);
            service();
            try (var boundary = new PermissionExecutionGuard(registry, users, null, policies).open(key)) {
                var response = plain.readTree(transport.writeValueAsString(new PermissionManifestRegistrationService.Result(receipt, "METADATA_PENDING", null)));
                assertThat(response.path("receipt").path("operationId").asText()).isEqualTo(receipt.operationId());
                assertThat(response.path("currentState").asText()).isEqualTo("METADATA_PENDING");
                assertThat(response.has("failureCode")).isTrue();
                verifyNoInteractions(policies);
            }
        }
    }

    private PermissionPolicyRegistry registry(String key) throws Exception {
        var fragment = new PermissionManifestReader().read(plain.readValue(Files.readString(
                Path.of("target/classes/META-INF/permissions/fragment-v1.json")), new TypeReference<Map<String, Object>>() { }));
        var source = fragment.producer();
        var full = new PermissionManifest(fragment.schemaVersion(), fragment.application(), new PermissionManifest.Producer(source.id(), source.kind(),
                PermissionManifest.SnapshotMode.FULL, source.ownedKeyPrefixes(), source.expectedModules(), source.scannedModules(), source.clearIntent()),
                fragment.artifact(), fragment.permissionDefinitions(), fragment.permissionReferences(), fragment.resources(), fragment.resourceReferences(), fragment.messages());
        return new PermissionPolicyRegistry(full, "a".repeat(64), Clock.fixed(NOW, ZoneOffset.UTC), List.of(TARGET), Set.of(key));
    }

    private void service() {
        var principal = new ServiceIdentityPrincipal("pipeline", "10", "pipeline", "token", URI.create("https://rbac.example"), 1,
                Set.of(REGISTER), "xingyuan", "ci", "test", "credential", NOW.minusSeconds(1), NOW.plusSeconds(100));
        SecurityContextHolder.getContext().setAuthentication(new IdpAuthenticationToken(principal, List.of(), URI.create("https://idp.example/tenants/10")));
    }
}
