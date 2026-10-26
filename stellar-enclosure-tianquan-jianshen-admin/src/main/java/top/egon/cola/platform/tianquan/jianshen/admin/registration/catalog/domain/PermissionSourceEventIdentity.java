package top.egon.cola.platform.tianquan.jianshen.admin.registration.catalog.domain;

import top.egon.cola.platform.tianquan.jianshen.contract.permission.CanonicalJson;

import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.util.HexFormat;
import java.util.Map;

/** Stable source-import identities shared by the producer, delivery handler and receipt recovery. */
public final class PermissionSourceEventIdentity {

    public static final String PERMISSION_SOURCE_CHANNEL = "tianquan-jianshen-permission-source";
    public static final String PERMISSION_SOURCE_DESTINATION = "tianquan-jianshen.permission.source-import.v1";

    private PermissionSourceEventIdentity() {
    }

    public static String permissionSourceAggregateId(String scopeId, String producerId, long revision) {
        return CanonicalJson.digest(Map.of("catalogScopeId", scopeId, "producerId", producerId,
                "producerVersion", Long.toString(revision)));
    }

    public static String permissionSourceMessageId(String tenantId, String scopeId, String producerId,
                                                    long revision, long metadataRevision) {
        String identity = tenantId + ':' + PERMISSION_SOURCE_DESTINATION + ':'
                + permissionSourceAggregateId(scopeId, producerId, revision) + ':' + metadataRevision;
        try {
            return HexFormat.of().formatHex(MessageDigest.getInstance("SHA-256")
                    .digest(identity.getBytes(StandardCharsets.UTF_8)));
        } catch (NoSuchAlgorithmException unavailable) {
            throw new IllegalStateException("SHA-256 is unavailable", unavailable);
        }
    }
}
