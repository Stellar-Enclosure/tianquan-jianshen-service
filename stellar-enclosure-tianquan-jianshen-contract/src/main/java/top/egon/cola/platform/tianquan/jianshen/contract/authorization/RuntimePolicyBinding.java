package top.egon.cola.platform.tianquan.jianshen.contract.authorization;

/** Trusted deployment evidence selected by the Runtime authority, compared with the executing build. */
public record RuntimePolicyBinding(String producerId, String producerVersion, String artifactDigest,
                                   String policyDigest, String manifestDigest) {
    public RuntimePolicyBinding {
        if (producerId == null || !producerId.matches("[A-Za-z][A-Za-z0-9_.:-]{0,127}")
                || producerVersion == null || !producerVersion.matches("[1-9][0-9]{0,18}")) {
            throw new IllegalArgumentException("runtime producer identity is invalid");
        }
        Long.parseLong(producerVersion);
        for (String value : java.util.List.of(artifactDigest, policyDigest, manifestDigest)) {
            if (!value.matches("[0-9a-f]{64}")) throw new IllegalArgumentException("runtime digest is invalid");
        }
    }
}
