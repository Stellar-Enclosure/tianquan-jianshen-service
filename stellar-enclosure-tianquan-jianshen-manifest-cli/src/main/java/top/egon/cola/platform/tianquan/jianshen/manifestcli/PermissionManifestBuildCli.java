package top.egon.cola.platform.tianquan.jianshen.manifestcli;

import com.fasterxml.jackson.core.JsonParser;
import com.fasterxml.jackson.core.StreamReadConstraints;
import com.fasterxml.jackson.core.type.TypeReference;
import com.fasterxml.jackson.databind.DeserializationFeature;
import com.fasterxml.jackson.databind.ObjectMapper;
import top.egon.cola.platform.tianquan.jianshen.contract.permission.CanonicalJson;
import top.egon.cola.platform.tianquan.jianshen.contract.permission.PermissionManifest;
import top.egon.cola.platform.tianquan.jianshen.contract.permission.PermissionManifestCanonicalizer;
import top.egon.cola.platform.tianquan.jianshen.contract.permission.PermissionManifestReader;
import top.egon.cola.platform.tianquan.jianshen.processor.PermissionManifestAggregator;

import java.io.IOException;
import java.io.InputStream;
import java.nio.charset.StandardCharsets;
import java.nio.file.AtomicMoveNotSupportedException;
import java.nio.file.Files;
import java.nio.file.LinkOption;
import java.nio.file.Path;
import java.nio.file.StandardCopyOption;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.util.ArrayList;
import java.util.Comparator;
import java.util.HexFormat;
import java.util.List;
import java.util.Map;
import java.util.jar.JarFile;

/** Runs after successful module compilation/tests and before the final host JAR is packaged. Never loads application classes. */
public final class PermissionManifestBuildCli {
    static final String FRAGMENT = "META-INF/permissions/fragment-v1.json";
    static final String MANIFEST = "META-INF/permissions/manifest-v1.json";
    static final String EVIDENCE = "META-INF/permissions/manifest-v1.evidence.json";
    private static final long MAX_MODULE_BYTES = 1024L * 1024 * 1024;
    private static final int MAX_MODULE_FILES = 100_000;
    private static final TypeReference<Map<String, Object>> OBJECT = new TypeReference<>() { };
    private final ObjectMapper json;

    public PermissionManifestBuildCli() {
        json = new ObjectMapper().enable(JsonParser.Feature.STRICT_DUPLICATE_DETECTION)
                .enable(DeserializationFeature.FAIL_ON_TRAILING_TOKENS);
        json.getFactory().setStreamReadConstraints(StreamReadConstraints.builder().maxNestingDepth(32)
                .maxStringLength(PermissionManifest.MAX_BYTES).build());
    }

    public static void main(String[] arguments) {
        try {
            Path output = null;
            Path artifact = null;
            boolean clearIntent = false;
            List<Path> modules = new ArrayList<>();
            for (int index = 0; index < arguments.length; index++) {
                String flag = arguments[index];
                if (flag.equals("--clear-intent")) {
                    if (clearIntent) throw new IllegalArgumentException("duplicate clear intent");
                    clearIntent = true;
                } else if ((flag.equals("--output") || flag.equals("--module") || flag.equals("--artifact")) && index + 1 < arguments.length) {
                    Path path = Path.of(arguments[++index]);
                    if (flag.equals("--output")) {
                        if (output != null) throw new IllegalArgumentException("duplicate output");
                        output = path;
                    } else if (flag.equals("--artifact")) {
                        if (artifact != null) throw new IllegalArgumentException("duplicate artifact");
                        artifact = path;
                    } else modules.add(path);
                } else throw new IllegalArgumentException("invalid build CLI argument");
            }
            if (output == null) throw new IllegalArgumentException("output is required");
            var cli = new PermissionManifestBuildCli();
            if (artifact == null) cli.build(modules, output, clearIntent);
            else {
                if (!modules.isEmpty() || clearIntent) throw new IllegalArgumentException("artifact evidence cannot aggregate modules");
                cli.verifyArtifact(artifact, output);
            }
        } catch (IOException | RuntimeException failure) {
            // Parser exceptions may contain source text. The command boundary reports no source payload or credential material.
            throw new IllegalArgumentException("Permission aggregation failed; check module artifacts, completeness, ownership and build provenance");
        }
    }

    public PermissionManifest build(List<Path> modulePaths, Path output, boolean clearIntent) throws IOException {
        if (modulePaths == null || modulePaths.isEmpty() || modulePaths.size() > 256) throw new IllegalArgumentException("invalid module count");
        Path destination = output.toAbsolutePath().normalize();
        if (Files.isSymbolicLink(destination) || !destination.getFileName().toString().equals("manifest-v1.json")) {
            throw new IllegalArgumentException("output must be a regular manifest-v1.json path");
        }
        List<PermissionManifestAggregator.BuiltModule> modules = new ArrayList<>();
        List<Map<String, Object>> evidence = new ArrayList<>();
        for (Path path : modulePaths) {
            Path artifact = path.toAbsolutePath().normalize();
            if (artifact.equals(destination) || Files.isSymbolicLink(artifact)) throw new IllegalArgumentException("invalid module path");
            boolean directory = Files.isDirectory(artifact, LinkOption.NOFOLLOW_LINKS);
            Module input = directory ? directory(artifact) : jar(artifact);
            modules.add(new PermissionManifestAggregator.BuiltModule(input.fragment(), input.digest()));
            evidence.add(Map.of("module", input.fragment().producer().scannedModules().getFirst(),
                    "kind", directory ? "COMPILED_DIRECTORY" : "PACKAGED_JAR", "inputDigest", input.digest()));
        }
        PermissionManifest manifest = new PermissionManifestAggregator().aggregate(modules, clearIntent);
        var canonicalizer = new PermissionManifestCanonicalizer();
        String canonical = canonicalizer.canonicalize(manifest);
        var digests = canonicalizer.digests(manifest);
        evidence.sort(Comparator.comparing(item -> item.get("module").toString()));
        String audit = CanonicalJson.write(Map.of("schemaVersion", "1.0", "producerId", manifest.producer().id(), "modules", evidence,
                "policyDigest", digests.policyDigest(), "metadataDigest", digests.metadataDigest(), "manifestDigest", digests.manifestDigest(),
                "boundary", "Successful compiled inputs only; deployment qualification requires the final packaged artifact digest"));
        // Both outputs are computed before either file is replaced. A failed/missing module cannot write a fresh FULL manifest.
        atomicWrite(destination.resolveSibling("manifest-v1.evidence.json"), audit);
        atomicWrite(destination, canonical);
        return manifest;
    }

    /** Binds the final packaged bytes to their embedded FULL manifest, without executing the host. */
    public Map<String, Object> verifyArtifact(Path artifactPath, Path output) throws IOException {
        Path artifact = artifactPath.toAbsolutePath().normalize();
        Path destination = output.toAbsolutePath().normalize();
        if (Files.isSymbolicLink(destination) || !destination.getFileName().toString().equals("artifact-evidence.json")
                || Files.isSymbolicLink(artifact) || !Files.isRegularFile(artifact, LinkOption.NOFOLLOW_LINKS)
                || Files.size(artifact) > MAX_MODULE_BYTES) {
            throw new IllegalArgumentException("regular packaged artifact and artifact-evidence.json output required");
        }
        Files.deleteIfExists(destination);
        String artifactDigest = digestFile(artifact);
        PermissionManifest manifest;
        Map<String, Object> embeddedEvidence;
        try (JarFile jar = new JarFile(artifact.toFile(), false)) {
            var entries = jar.stream().limit(MAX_MODULE_FILES + 1L).toList();
            var manifests = entries.stream().filter(entry -> entry.getName().equals(MANIFEST)
                    || entry.getName().equals("BOOT-INF/classes/" + MANIFEST)).toList();
            if (entries.size() > MAX_MODULE_FILES || manifests.size() != 1
                    || entries.stream().noneMatch(entry -> entry.getName().endsWith(".class"))) {
                throw new IllegalArgumentException("artifact requires one embedded FULL manifest and compiled classes");
            }
            var manifestEntry = manifests.getFirst();
            String evidencePath = manifestEntry.getName().replace("manifest-v1.json", "manifest-v1.evidence.json");
            if (entries.stream().filter(entry -> entry.getName().equals(evidencePath)).count() != 1) {
                throw new IllegalArgumentException("embedded module evidence is required");
            }
            try (InputStream input = jar.getInputStream(manifestEntry)) { manifest = fragment(input); }
            try (InputStream input = jar.getInputStream(jar.getJarEntry(evidencePath))) {
                byte[] bytes = input.readNBytes(PermissionManifest.MAX_BYTES + 1);
                if (bytes.length > PermissionManifest.MAX_BYTES) throw new IllegalArgumentException("evidence exceeds byte limit");
                embeddedEvidence = json.readValue(bytes, OBJECT);
            }
        }
        var canonicalizer = new PermissionManifestCanonicalizer();
        var digests = canonicalizer.digests(manifest);
        if (manifest.producer().snapshotMode() != PermissionManifest.SnapshotMode.FULL
                || !new java.util.HashSet<>(manifest.producer().expectedModules()).equals(new java.util.HashSet<>(manifest.producer().scannedModules()))
                || !manifest.producer().id().equals(embeddedEvidence.get("producerId"))
                || !digests.policyDigest().equals(embeddedEvidence.get("policyDigest"))
                || !digests.metadataDigest().equals(embeddedEvidence.get("metadataDigest"))
                || !digests.manifestDigest().equals(embeddedEvidence.get("manifestDigest"))) {
            throw new IllegalArgumentException("embedded completeness or digest mismatch");
        }
        if (!(embeddedEvidence.get("modules") instanceof List<?> modules) || modules.size() != manifest.producer().scannedModules().size()) {
            throw new IllegalArgumentException("embedded module inputs are incomplete");
        }
        var moduleIds = new java.util.HashSet<String>();
        for (Object item : modules) {
            if (!(item instanceof Map<?, ?> module) || !(module.get("module") instanceof String id) || !moduleIds.add(id)
                    || !(module.get("inputDigest") instanceof String digest) || !digest.matches("[a-f0-9]{64}")
                    || !List.of("COMPILED_DIRECTORY", "PACKAGED_JAR").contains(module.get("kind"))) {
                throw new IllegalArgumentException("embedded module evidence is invalid");
            }
        }
        if (!moduleIds.equals(new java.util.HashSet<>(manifest.producer().scannedModules())) || !artifactDigest.equals(digestFile(artifact))) {
            throw new IllegalArgumentException("artifact changed or module inputs mismatch");
        }
        Map<String, Object> evidence = new java.util.TreeMap<>();
        evidence.put("schemaVersion", "1.0");
        evidence.put("producerId", manifest.producer().id());
        evidence.put("artifactFile", artifact.getFileName().toString());
        evidence.put("artifactDigest", artifactDigest);
        evidence.put("manifestDigest", digests.manifestDigest());
        evidence.put("policyDigest", digests.policyDigest());
        evidence.put("metadataDigest", digests.metadataDigest());
        evidence.put("artifact", Map.of("repository", manifest.artifact().repository(), "commit", manifest.artifact().commit(),
                "buildId", manifest.artifact().buildId(), "version", manifest.artifact().version()));
        evidence.put("modules", embeddedEvidence.get("modules"));
        evidence.put("boundary", "Packaged bytes verified; deployment and readiness are separate trusted assertions");
        atomicWrite(destination.resolveSibling("manifest-v1.json"), canonicalizer.canonicalize(manifest));
        atomicWrite(destination, CanonicalJson.write(evidence));
        return Map.copyOf(evidence);
    }

    private Module jar(Path path) throws IOException {
        if (!Files.isRegularFile(path, LinkOption.NOFOLLOW_LINKS) || Files.size(path) > MAX_MODULE_BYTES) throw new IllegalArgumentException("invalid module JAR");
        try (JarFile jar = new JarFile(path.toFile(), false)) {
            var entries = jar.stream().limit(MAX_MODULE_FILES + 1L).toList();
            if (entries.size() > MAX_MODULE_FILES || entries.stream().filter(entry -> entry.getName().equals(FRAGMENT)).count() != 1
                    || entries.stream().noneMatch(entry -> entry.getName().endsWith(".class"))) {
                throw new IllegalArgumentException("module JAR needs compiled classes and one fragment");
            }
            PermissionManifest fragment;
            try (InputStream stream = jar.getInputStream(jar.getJarEntry(FRAGMENT))) { fragment = fragment(stream); }
            return new Module(fragment, digestFile(path));
        }
    }

    private Module directory(Path path) throws IOException {
        List<Path> files;
        try (var walk = Files.walk(path)) {
            files = walk.filter(file -> !Files.isDirectory(file, LinkOption.NOFOLLOW_LINKS)).limit(MAX_MODULE_FILES + 1L).sorted().toList();
        }
        if (files.size() > MAX_MODULE_FILES || files.stream().noneMatch(file -> file.toString().endsWith(".class"))) {
            throw new IllegalArgumentException("module directory needs bounded compiled classes");
        }
        MessageDigest digest = sha256();
        long total = 0;
        for (Path file : files) {
            if (Files.isSymbolicLink(file) || !Files.isRegularFile(file, LinkOption.NOFOLLOW_LINKS)) throw new IllegalArgumentException("module files must be regular files");
            String relative = path.relativize(file).toString().replace('\\', '/');
            if (relative.equals(MANIFEST) || relative.equals(EVIDENCE)) continue;
            total = Math.addExact(total, Files.size(file));
            if (total > MAX_MODULE_BYTES) throw new IllegalArgumentException("compiled module exceeds byte limit");
            digest.update(relative.getBytes(StandardCharsets.UTF_8));
            digest.update((byte) 0);
            digest.update(digestFile(file).getBytes(StandardCharsets.US_ASCII));
            digest.update((byte) '\n');
        }
        PermissionManifest fragment;
        try (InputStream input = Files.newInputStream(path.resolve(FRAGMENT))) { fragment = fragment(input); }
        return new Module(fragment, HexFormat.of().formatHex(digest.digest()));
    }

    private PermissionManifest fragment(InputStream input) throws IOException {
        byte[] bytes = input.readNBytes(PermissionManifest.MAX_BYTES + 1);
        if (bytes.length > PermissionManifest.MAX_BYTES) throw new IllegalArgumentException("module fragment exceeds byte limit");
        return new PermissionManifestReader().read(json.readValue(bytes, OBJECT));
    }

    private String digestFile(Path path) throws IOException {
        var before = Files.readAttributes(path, java.nio.file.attribute.BasicFileAttributes.class, LinkOption.NOFOLLOW_LINKS);
        MessageDigest digest = sha256();
        try (InputStream input = Files.newInputStream(path)) {
            byte[] buffer = new byte[64 * 1024];
            long size = 0;
            int count;
            while ((count = input.read(buffer)) != -1) {
                size += count;
                if (size > MAX_MODULE_BYTES) throw new IllegalArgumentException("module file exceeds byte limit");
                digest.update(buffer, 0, count);
            }
        }
        var after = Files.readAttributes(path, java.nio.file.attribute.BasicFileAttributes.class, LinkOption.NOFOLLOW_LINKS);
        if (before.size() != after.size() || !before.lastModifiedTime().equals(after.lastModifiedTime())) throw new IOException("module changed while reading");
        return HexFormat.of().formatHex(digest.digest());
    }

    private void atomicWrite(Path output, String text) throws IOException {
        Files.createDirectories(output.getParent());
        Path temporary = Files.createTempFile(output.getParent(), ".permission-manifest-", ".tmp");
        try {
            Files.writeString(temporary, text, StandardCharsets.UTF_8);
            try { Files.move(temporary, output, StandardCopyOption.ATOMIC_MOVE, StandardCopyOption.REPLACE_EXISTING); }
            catch (AtomicMoveNotSupportedException unsupported) { Files.move(temporary, output, StandardCopyOption.REPLACE_EXISTING); }
        } finally { Files.deleteIfExists(temporary); }
    }

    private static MessageDigest sha256() {
        try { return MessageDigest.getInstance("SHA-256"); }
        catch (NoSuchAlgorithmException impossible) { throw new IllegalStateException("SHA-256 unavailable", impossible); }
    }

    private record Module(PermissionManifest fragment, String digest) { }
}
