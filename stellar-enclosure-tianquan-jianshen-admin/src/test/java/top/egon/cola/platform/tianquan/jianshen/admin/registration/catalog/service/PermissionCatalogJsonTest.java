package top.egon.cola.platform.tianquan.jianshen.admin.registration.catalog.service;

import top.egon.cola.platform.tianquan.jianshen.admin.registration.catalog.domain.convertor.PermissionCatalogJson;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.datatype.jsr310.JavaTimeModule;
import org.junit.jupiter.api.Test;
import top.egon.cola.platform.tianquan.jianshen.contract.permission.ManifestRegistrationRequest;

import java.io.ByteArrayInputStream;
import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.util.LinkedHashMap;
import java.util.Map;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;

class PermissionCatalogJsonTest {

    private final PermissionCatalogJson json = new PermissionCatalogJson(new ObjectMapper().registerModule(new JavaTimeModule()));

    @Test
    void strictlyRoundTripsThePlanEnvelope() throws Exception {
        var plan = new ManifestRegistrationRequest.Plan(PermissionCatalogFixture.SCOPE, PermissionCatalogFixture.manifest(), "0", "0");
        var actual = json.plan(json.readObject(input(json.write(plan))));
        assertEquals(plan.requestDigest(), actual.requestDigest());
    }

    @Test
    void duplicateKeysAndTrailingValuesAreRejected() {
        assertThrows(IOException.class, () -> json.readObject(input("{\"target\":1,\"target\":2}")));
        assertThrows(IOException.class, () -> json.readObject(input("{} {}")));
    }

    @Test
    void unknownEnvelopeAndTargetFieldsAreRejected() {
        var plan = new ManifestRegistrationRequest.Plan(PermissionCatalogFixture.SCOPE, PermissionCatalogFixture.manifest(), "0", "0");
        Map<String, Object> value = new LinkedHashMap<>(json.readObject(json.write(plan)));
        value.put("activate", true);
        assertThrows(IllegalArgumentException.class, () -> json.plan(value));
        value.remove("activate");
        Map<String, Object> target = new LinkedHashMap<>(ManifestRegistrationRequest.targetMap(PermissionCatalogFixture.SCOPE));
        target.put("roleIds", java.util.List.of("1"));
        value.put("target", target);
        assertThrows(IllegalArgumentException.class, () -> json.plan(value));
    }

    @Test
    void numericIdsAndRevisionsDoNotCoerceIntoStrings() {
        var plan = new ManifestRegistrationRequest.Plan(PermissionCatalogFixture.SCOPE, PermissionCatalogFixture.manifest(), "0", "0");
        Map<String, Object> value = new LinkedHashMap<>(json.readObject(json.write(plan)));
        value.put("expectedProducerRevision", 0);
        assertThrows(IllegalArgumentException.class, () -> json.plan(value));
    }

    @Test
    void excessiveNestingAndByteSizeAreRejectedBeforeDomainConversion() {
        assertThrows(IOException.class, () -> json.readObject(input("[".repeat(18) + "0" + "]".repeat(18))));
        assertThrows(IllegalArgumentException.class, () -> json.readObject(new ByteArrayInputStream(new byte[PermissionCatalogJson.MAX_ENVELOPE_BYTES + 1])));
    }

    private ByteArrayInputStream input(String value) {
        return new ByteArrayInputStream(value.getBytes(StandardCharsets.UTF_8));
    }
}
