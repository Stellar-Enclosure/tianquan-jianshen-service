package top.egon.cola.platform.tianquan.jianshen.processor;

import top.egon.cola.platform.tianquan.jianshen.contract.permission.PermissionManifest;
import top.egon.cola.platform.tianquan.jianshen.contract.permission.PermissionManifestCanonicalizer;

import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.HashSet;
import java.util.List;
import java.util.Set;
import java.util.TreeSet;

/** Pure aggregation used only after every expected module has successfully built its artifact. */
public final class PermissionManifestAggregator {

    /** The build orchestrator supplies the digest only after a successful compiler/package exit. */
    public record BuiltModule(PermissionManifest fragment, String artifactDigest) {
        public BuiltModule {
            if (fragment == null || artifactDigest == null || !artifactDigest.matches("[0-9a-f]{64}")) {
                throw new IllegalArgumentException("successful module artifact evidence is required");
            }
            if (fragment.producer().snapshotMode() != PermissionManifest.SnapshotMode.PARTIAL
                    || fragment.producer().scannedModules().size() != 1 || fragment.producer().clearIntent()) {
                throw new IllegalArgumentException("expected a single module fragment");
            }
        }
    }

    public PermissionManifest aggregate(List<BuiltModule> modules, boolean clearIntent) {
        if (modules == null || modules.isEmpty()) throw new IllegalArgumentException("no successful module artifacts");
        PermissionManifest first = modules.getFirst().fragment();
        PermissionManifest.Producer producer = first.producer();
        Set<String> scanned = new TreeSet<>();
        List<PermissionManifest.PermissionDefinition> definitions = new ArrayList<>();
        Set<String> references = new TreeSet<>();
        List<PermissionManifest.ResourceDefinition> resources = new ArrayList<>();
        Set<PermissionManifest.ResourceReference> resourceReferences = new HashSet<>();
        List<PermissionManifest.Message> messages = new ArrayList<>();
        for (BuiltModule module : modules) {
            PermissionManifest fragment = module.fragment();
            PermissionManifest.Producer member = fragment.producer();
            if (!fragment.application().equals(first.application()) || !fragment.artifact().equals(first.artifact())
                    || !member.id().equals(producer.id()) || member.kind() != producer.kind()
                    || !member.ownedKeyPrefixes().equals(producer.ownedKeyPrefixes())
                    || !member.expectedModules().equals(producer.expectedModules())) {
                throw new IllegalArgumentException("module provenance or producer contract differs");
            }
            if (!scanned.add(member.scannedModules().getFirst())) throw new IllegalArgumentException("duplicate module artifact");
            definitions.addAll(fragment.permissionDefinitions());
            references.addAll(fragment.permissionReferences());
            resources.addAll(fragment.resources());
            resourceReferences.addAll(fragment.resourceReferences());
            messages.addAll(fragment.messages());
        }
        if (!scanned.equals(new TreeSet<>(producer.expectedModules()))) {
            throw new IllegalArgumentException("missing expected module artifacts");
        }
        definitions.forEach(definition -> references.remove(definition.code()));
        Set<String> ownedResources = new HashSet<>();
        resources.forEach(resource -> ownedResources.add(resource.key()));
        resourceReferences.removeIf(reference -> ownedResources.contains(reference.key()));
        PermissionManifest result = new PermissionManifest(first.schemaVersion(), first.application(),
                new PermissionManifest.Producer(producer.id(), producer.kind(), PermissionManifest.SnapshotMode.FULL,
                        producer.ownedKeyPrefixes(), producer.expectedModules(), List.copyOf(scanned), clearIntent),
                first.artifact(), definitions, List.copyOf(references), resources, List.copyOf(resourceReferences), messages);
        if (new PermissionManifestCanonicalizer().canonicalize(result).getBytes(StandardCharsets.UTF_8).length > PermissionManifest.MAX_BYTES) {
            throw new IllegalArgumentException("aggregate manifest exceeds byte limit");
        }
        return result;
    }
}
