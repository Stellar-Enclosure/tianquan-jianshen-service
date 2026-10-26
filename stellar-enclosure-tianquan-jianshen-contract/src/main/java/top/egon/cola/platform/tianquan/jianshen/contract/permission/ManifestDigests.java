package top.egon.cola.platform.tianquan.jianshen.contract.permission;

public record ManifestDigests(
        String policyDigest,
        String metadataDigest,
        String manifestDigest
) {

    public ManifestDigests {
        policyDigest = ManifestChecks.hash(policyDigest, "policyDigest");
        metadataDigest = ManifestChecks.hash(metadataDigest, "metadataDigest");
        manifestDigest = ManifestChecks.hash(manifestDigest, "manifestDigest");
    }
}
