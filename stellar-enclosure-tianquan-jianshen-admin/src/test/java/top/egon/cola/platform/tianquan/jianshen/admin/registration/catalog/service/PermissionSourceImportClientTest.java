package top.egon.cola.platform.tianquan.jianshen.admin.registration.catalog.service;

import top.egon.cola.platform.tianquan.jianshen.admin.registration.catalog.domain.convertor.PermissionCatalogJson;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.datatype.jsr310.JavaTimeModule;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.springframework.http.HttpMethod;
import org.springframework.http.HttpStatus;
import org.springframework.http.MediaType;
import org.springframework.security.oauth2.core.OAuth2AccessToken;
import org.springframework.test.web.client.MockRestServiceServer;
import org.springframework.web.client.RestClient;
import top.egon.cola.component.common.core.pojo.ResultRecord;
import top.egon.cola.platform.tianquan.jianshen.admin.config.permission.PermissionMetadataProperties;
import top.egon.cola.platform.tianquan.jianshen.contract.permission.CatalogScope;
import top.egon.cola.platform.tianquan.jianshen.contract.permission.PermissionManifestCanonicalizer;
import top.egon.cola.platform.tianquan.jianshen.contract.permission.SourceImportReceipt;
import top.egon.cola.platform.tianquan.jianshen.contract.permission.SourceImportRequest;
import top.egon.cola.platform.tianquan.shoubing.starter.client.IdpServiceOAuth2Client;

import java.net.URI;
import java.util.Map;

import static org.hamcrest.Matchers.startsWith;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.times;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.verifyNoInteractions;
import static org.mockito.Mockito.when;
import static org.springframework.test.web.client.match.MockRestRequestMatchers.header;
import static org.springframework.test.web.client.match.MockRestRequestMatchers.method;
import static org.springframework.test.web.client.match.MockRestRequestMatchers.queryParam;
import static org.springframework.test.web.client.match.MockRestRequestMatchers.requestTo;
import static org.springframework.test.web.client.response.MockRestResponseCreators.withStatus;
import static org.springframework.test.web.client.response.MockRestResponseCreators.withSuccess;

class PermissionSourceImportClientTest {

    private final PermissionCatalogJson json = new PermissionCatalogJson(new ObjectMapper().registerModule(new JavaTimeModule()));
    private final PermissionMetadataProperties properties = new PermissionMetadataProperties();
    private final IdpServiceOAuth2Client oauth = mock(IdpServiceOAuth2Client.class);
    private MockRestServiceServer server;
    private PermissionSourceImportClient client;
    private SourceImportRequest source;
    private SourceImportReceipt receipt;

    @BeforeEach
    void prepare() {
        var manifest = PermissionCatalogFixture.manifest();
        var digests = new PermissionManifestCanonicalizer().digests(manifest);
        source = new SourceImportRequest(PermissionCatalogFixture.OPERATION, PermissionCatalogFixture.SCOPE, "api", "1", digests.manifestDigest(),
                manifest, digests, Map.of("app.read", "101"), Map.of("app.read", "201"));
        receipt = new SourceImportReceipt("300", source.operationId(), source.scope(), source.producerId(), source.producerVersion(),
                source.sourceVersion(), source.digests(), source.projectionDigest(), 1, 1, 1, PermissionCatalogFixture.NOW);
        properties.setBindings(Map.of("1", new PermissionMetadataProperties.Binding(PermissionCatalogFixture.SCOPE,
                URI.create("https://metadata.example/"), "metadata", "publisher-app", URI.create("https://metadata.example"))));
        var builder = RestClient.builder();
        server = MockRestServiceServer.bindTo(builder).build();
        client = new PermissionSourceImportClient(properties, oauth, json, builder.build());
        when(oauth.authorize(any())).thenReturn(new OAuth2AccessToken(OAuth2AccessToken.TokenType.BEARER, "test-service-proof",
                PermissionCatalogFixture.NOW.minusSeconds(1), PermissionCatalogFixture.NOW.plusSeconds(60)));
    }

    @Test
    void lookupUsesFullTargetAndOriginalOperation() {
        server.expect(requestTo(startsWith("https://metadata.example/internal/v1/i18n/source-imports/" + source.operationId())))
                .andExpect(method(HttpMethod.GET)).andExpect(queryParam("catalogScopeId", "1")).andExpect(queryParam("tenantId", "10"))
                .andExpect(queryParam("namespaceCode", "default")).andExpect(queryParam("producerId", "api"))
                .andExpect(header("Authorization", "Bearer test-service-proof"))
                .andRespond(withSuccess(json.write(ResultRecord.success(receipt)), MediaType.APPLICATION_JSON));
        assertEquals(receipt, client.lookup(source).orElseThrow());
        server.verify();
    }

    @Test
    void onlyDefiniteNotFoundReturnsAnAbsentReceipt() {
        server.expect(requestTo(startsWith("https://metadata.example/internal/v1/i18n/source-imports/")))
                .andRespond(withStatus(HttpStatus.NOT_FOUND));
        assertTrue(client.lookup(source).isEmpty());
        server.verify();
    }

    @Test
    void postRequiresExactReceiptAndTheRealResultRecordSuccessCode() {
        server.expect(requestTo("https://metadata.example/internal/v1/i18n/source-imports"))
                .andExpect(method(HttpMethod.POST)).andRespond(withSuccess(json.write(ResultRecord.success(receipt)), MediaType.APPLICATION_JSON));
        assertEquals(receipt, client.importSource(source));
        server.verify();
    }

    @Test
    void one401InvalidatesMachineTokenAndRetriesSameOperation() {
        server.expect(requestTo("https://metadata.example/internal/v1/i18n/source-imports")).andRespond(withStatus(HttpStatus.UNAUTHORIZED));
        server.expect(requestTo("https://metadata.example/internal/v1/i18n/source-imports"))
                .andRespond(withSuccess(json.write(ResultRecord.success(receipt)), MediaType.APPLICATION_JSON));
        assertEquals(receipt, client.importSource(source));
        verify(oauth).invalidate(any());
        verify(oauth, times(2)).authorize(any());
        server.verify();
    }

    @Test
    void forbiddenIsPermanentAndUnavailableIsRetryable() {
        server.expect(requestTo("https://metadata.example/internal/v1/i18n/source-imports")).andRespond(withStatus(HttpStatus.FORBIDDEN));
        assertFalse(assertThrows(PermissionSourceImportClient.MetadataTransferFailure.class, () -> client.importSource(source)).retryable());
        server.verify();
        server.reset();
        server.expect(requestTo("https://metadata.example/internal/v1/i18n/source-imports")).andRespond(withStatus(HttpStatus.SERVICE_UNAVAILABLE));
        assertTrue(assertThrows(PermissionSourceImportClient.MetadataTransferFailure.class, () -> client.importSource(source)).retryable());
        server.verify();
    }

    @Test
    void crossScopeReceiptCannotAdvanceTheCandidate() {
        var other = new SourceImportReceipt("300", source.operationId(), new CatalogScope("1", "11", "biz", "app", "default", "test"),
                source.producerId(), source.producerVersion(), source.sourceVersion(), source.digests(), source.projectionDigest(), 1, 1, 1, PermissionCatalogFixture.NOW);
        server.expect(requestTo("https://metadata.example/internal/v1/i18n/source-imports"))
                .andRespond(withSuccess(json.write(ResultRecord.success(other)), MediaType.APPLICATION_JSON));
        var failure = assertThrows(PermissionSourceImportClient.MetadataTransferFailure.class, () -> client.importSource(source));
        assertEquals("METADATA_RECEIPT_MISMATCH", failure.getMessage());
        assertFalse(failure.retryable());
    }

    @Test
    void missingBindingDoesNotSendCredentialsToAnUnselectedTarget() {
        properties.setBindings(Map.of());
        assertTrue(assertThrows(PermissionSourceImportClient.MetadataTransferFailure.class, () -> client.lookup(source)).retryable());
        verifyNoInteractions(oauth);
        server.verify();
    }

    @Test
    void plaintextAndCredentialBearingDestinationUrisAreRejected() {
        assertThrows(IllegalArgumentException.class, () -> new PermissionMetadataProperties.Binding(PermissionCatalogFixture.SCOPE,
                URI.create("http://metadata.example/"), "metadata", "publisher", URI.create("https://metadata.example")));
        assertThrows(IllegalArgumentException.class, () -> new PermissionMetadataProperties.Binding(PermissionCatalogFixture.SCOPE,
                URI.create("https://user:password@metadata.example/"), "metadata", "publisher", URI.create("https://metadata.example")));
    }
}
