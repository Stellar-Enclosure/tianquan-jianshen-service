package top.egon.cola.platform.tianquan.jianshen.admin.registration.catalog.service;

import top.egon.cola.platform.tianquan.jianshen.admin.registration.catalog.domain.convertor.PermissionCatalogJson;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.HttpMethod;
import org.springframework.http.MediaType;
import org.springframework.http.client.JdkClientHttpRequestFactory;
import org.springframework.stereotype.Component;
import org.springframework.web.client.RestClient;
import org.springframework.web.util.UriComponentsBuilder;
import top.egon.cola.component.common.core.enums.ResultCode;
import top.egon.cola.platform.tianquan.jianshen.admin.config.permission.PermissionMetadataProperties;
import top.egon.cola.platform.tianquan.jianshen.contract.permission.ManifestRegistrationRequest;
import top.egon.cola.platform.tianquan.jianshen.contract.permission.SourceImportReceipt;
import top.egon.cola.platform.tianquan.jianshen.contract.permission.SourceImportRequest;
import top.egon.cola.platform.tianquan.shoubing.contract.ServiceTokenContext;
import top.egon.cola.platform.tianquan.shoubing.starter.client.IdpServiceOAuth2Client;
import top.egon.cola.platform.tianquan.shoubing.starter.client.IdpServiceTokenRequest;

import java.net.URI;
import java.io.ByteArrayInputStream;
import java.io.IOException;
import java.net.http.HttpClient;
import java.time.Duration;
import java.util.Map;
import java.util.Optional;
import java.util.Set;

/** Idempotent metadata transfer over a fixed HTTPS authority, with bounded response and no redirects. */
@Component
public class PermissionSourceImportClient {

    private static final String SCOPE = "TIANSHU_METADATA_IMPORT";
    private static final String PATH = "internal/v1/i18n/source-imports";
    private static final int MAX_RECEIPT_BYTES = 64 * 1024;
    private final PermissionMetadataProperties properties;
    private final IdpServiceOAuth2Client oauth;
    private final PermissionCatalogJson json;
    private final RestClient transport;

    @Autowired
    public PermissionSourceImportClient(PermissionMetadataProperties properties, IdpServiceOAuth2Client oauth, PermissionCatalogJson json) {
        this(properties, oauth, json, boundedTransport());
    }

    PermissionSourceImportClient(PermissionMetadataProperties properties, IdpServiceOAuth2Client oauth, PermissionCatalogJson json, RestClient transport) {
        this.properties = properties;
        this.oauth = oauth;
        this.json = json;
        this.transport = transport;
    }

    public Optional<SourceImportReceipt> lookup(SourceImportRequest request) {
        return exchange(request, false);
    }

    public SourceImportReceipt importSource(SourceImportRequest request) {
        return exchange(request, true).orElseThrow(() -> new MetadataTransferFailure("METADATA_RECEIPT_MISSING", false));
    }

    private Optional<SourceImportReceipt> exchange(SourceImportRequest request, boolean write) {
        var binding = properties.getBindings().get(request.scope().catalogScopeId());
        if (binding == null || !binding.target().equals(request.scope())) {
            throw new MetadataTransferFailure("METADATA_TARGET_NOT_CONFIGURED", true);
        }
        var tokenRequest = new IdpServiceTokenRequest(binding.registrationId(), binding.appId(), binding.resourceUri(),
                ServiceTokenContext.TENANT, request.scope().tenantId(), Set.of(SCOPE));
        URI destination = binding.baseUri().resolve(PATH);
        if (!write) {
            var uri = UriComponentsBuilder.fromUri(binding.baseUri().resolve(PATH + '/' + request.operationId()));
            ManifestRegistrationRequest.targetMap(request.scope()).forEach(uri::queryParam);
            uri.queryParam("producerId", request.producerId());
            destination = uri.build().encode().toUri();
        }
        String payload = write ? json.write(request) : null;
        try {
            for (int attempt = 0; attempt < 2; attempt++) {
                String token = oauth.authorize(tokenRequest).getTokenValue();
                var http = transport.method(write ? HttpMethod.POST : HttpMethod.GET).uri(destination)
                        .headers(headers -> headers.setBearerAuth(token)).accept(MediaType.APPLICATION_JSON);
                if (write) http.contentType(MediaType.APPLICATION_JSON).body(payload);
                Exchange response = http.exchange((outgoing, incoming) -> {
                    int status = incoming.getStatusCode().value();
                    if (status == 401 || status == 404 && !write) return new Exchange(status, null);
                    if (status != 200) throw new MetadataTransferFailure("METADATA_HTTP_" + status, status >= 500 || status == 429);
                    byte[] bytes = incoming.getBody().readNBytes(MAX_RECEIPT_BYTES + 1);
                    if (bytes.length > MAX_RECEIPT_BYTES) throw new MetadataTransferFailure("METADATA_RECEIPT_TOO_LARGE", false);
                    Map<String, Object> envelope;
                    try {
                        envelope = json.readObject(new ByteArrayInputStream(bytes));
                    } catch (IOException invalid) {
                        throw new MetadataTransferFailure("METADATA_RECEIPT_INVALID", false);
                    }
                    PermissionCatalogJson.fields(envelope, "success", "code", "status", "message", "data", "traceId", "timestamp");
                    if (!Boolean.TRUE.equals(envelope.get("success")) || !Integer.valueOf(ResultCode.SUCCESS.getCode()).equals(envelope.get("code"))) {
                        throw new MetadataTransferFailure("METADATA_RECEIPT_INVALID", false);
                    }
                    SourceImportReceipt receipt = json.read(json.write(PermissionCatalogJson.object(envelope, "data")), SourceImportReceipt.class);
                    if (!receipt.matches(request)) throw new MetadataTransferFailure("METADATA_RECEIPT_MISMATCH", false);
                    return new Exchange(status, receipt);
                });
                if (response == null) throw new MetadataTransferFailure("METADATA_RESPONSE_MISSING", true);
                if (response.status() == 404) return Optional.empty();
                if (response.status() == 200) return Optional.of(response.receipt());
                oauth.invalidate(tokenRequest);
            }
            throw new MetadataTransferFailure("METADATA_SERVICE_AUTHENTICATION_REJECTED", false);
        } catch (MetadataTransferFailure failure) {
            throw failure;
        } catch (IllegalArgumentException invalid) {
            throw new MetadataTransferFailure("METADATA_RECEIPT_INVALID", false);
        } catch (RuntimeException unavailable) {
            throw new MetadataTransferFailure("METADATA_AUTHORITY_UNAVAILABLE", true);
        }
    }

    private static RestClient boundedTransport() {
        Duration timeout = Duration.ofSeconds(5);
        HttpClient client = HttpClient.newBuilder().connectTimeout(timeout).followRedirects(HttpClient.Redirect.NEVER).build();
        JdkClientHttpRequestFactory factory = new JdkClientHttpRequestFactory(client);
        factory.setReadTimeout(timeout);
        return RestClient.builder().requestFactory(factory).build();
    }

    private record Exchange(int status, SourceImportReceipt receipt) { }

    public static final class MetadataTransferFailure extends RuntimeException {
        private final boolean retryable;

        public MetadataTransferFailure(String code, boolean retryable) {
            super(code);
            this.retryable = retryable;
        }

        public boolean retryable() {
            return retryable;
        }
    }
}
