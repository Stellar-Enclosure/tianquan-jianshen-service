package top.egon.cola.platform.tianquan.jianshen.core.registration;

import org.junit.jupiter.api.Test;
import top.egon.cola.platform.tianquan.jianshen.contract.permission.DefinitionLifecycle;
import top.egon.cola.platform.tianquan.jianshen.contract.permission.PermissionManifest;
import top.egon.cola.platform.tianquan.jianshen.contract.permission.PermissionMode;
import top.egon.cola.platform.tianquan.jianshen.contract.permission.PermissionRequirement;
import top.egon.cola.platform.tianquan.jianshen.contract.permission.ResourceAccess;
import top.egon.cola.platform.tianquan.jianshen.contract.permission.ResourceType;

import java.util.ArrayList;
import java.util.HashSet;
import java.util.List;
import java.util.Map;
import java.util.Set;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;

class PermissionManifestDiffTest {

    private final PermissionManifestDiff diff = new PermissionManifestDiff();

    @Test
    void implicationMatchesExhaustiveTruthTables() {
        List<PermissionRequirement> expressions = new ArrayList<>();
        expressions.add(PermissionRequirement.publicAccess());
        for (int mask = 1; mask < 8; mask++) {
            List<String> codes = new ArrayList<>();
            for (int bit = 0; bit < 3; bit++) if ((mask & (1 << bit)) != 0) codes.add("demo." + (char) ('a' + bit));
            for (PermissionMode mode : PermissionMode.values()) expressions.add(new PermissionRequirement(mode, codes));
        }
        List<PermissionRequirement> groups = List.copyOf(expressions);
        for (PermissionRequirement left : groups) for (PermissionRequirement right : groups) {
            expressions.add(PermissionRequirement.allOf(List.of(left, right)));
        }
        for (PermissionRequirement candidate : expressions) for (PermissionRequirement required : expressions) {
            boolean implies = true;
            for (int mask = 0; mask < 8; mask++) {
                Set<String> codes = new HashSet<>();
                for (int bit = 0; bit < 3; bit++) if ((mask & (1 << bit)) != 0) codes.add("demo." + (char) ('a' + bit));
                if (candidate.allows(codes) && !required.allows(codes)) implies = false;
            }
            assertEquals(implies, diff.implies(candidate, required), () -> candidate + " => " + required);
        }
    }

    @Test
    void allToAnyAndRemovedGroupsAreExpansion() {
        var all = group(PermissionMode.ALL, "demo.a", "demo.b");
        var any = group(PermissionMode.ANY, "demo.a", "demo.b");
        assertTrue(compare(api("demo.read", all), api("demo.read", any)).authorizationExpansion());
        assertFalse(compare(api("demo.read", any), api("demo.read", all)).authorizationExpansion());
        var combined = PermissionRequirement.allOf(List.of(any, group(PermissionMode.ALL, "demo.c")));
        assertTrue(compare(api("demo.read", combined), api("demo.read", any)).authorizationExpansion());
    }

    @Test
    void newResourceUsingGrantedPermissionIsVisible() {
        var report = diff.compare(null, manifest(List.of(api("demo.read", group(PermissionMode.ALL, "demo.a"))), false), Set.of("demo.a"));
        assertTrue(report.authorizationExpansion());
        assertTrue(report.entries().stream().anyMatch(entry -> entry.reason().equals("NEW_RESOURCE_USES_GRANTED_PERMISSION")));
        assertFalse(diff.compare(null, manifest(List.of(api("demo.read", group(PermissionMode.ALL, "demo.a"))), false), Set.of()).authorizationExpansion());
    }

    @Test
    void publicClassificationAndTargetChangesRequireReview() {
        var original = api("demo.read", group(PermissionMode.ALL, "demo.a"));
        var publicResource = new PermissionManifest.ResourceDefinition(original.key(), original.type(), original.target(),
                ResourceAccess.PUBLIC, null, null, original.allowedPrincipals(), original.oauthScopes(), original.i18n(), original.lifecycle());
        assertTrue(compare(original, publicResource).authorizationExpansion());
        var target = new PermissionManifest.ResourceDefinition(original.key(), original.type(), Map.of("path", "/all"),
                original.access(), original.requirement(), null, original.allowedPrincipals(), original.oauthScopes(), original.i18n(), original.lifecycle());
        assertTrue(compare(original, target).authorizationExpansion());
    }

    @Test
    void independentFieldOperationsCannotHideWriteOrPlainReadExpansion() {
        var a = group(PermissionMode.ALL, "demo.a");
        var b = group(PermissionMode.ANY, "demo.a", "demo.b");
        var old = field(a, a, null);
        var writeAdded = field(a, a, b);
        var report = compare(old, writeAdded);
        assertTrue(report.entries().stream().anyMatch(entry -> entry.reason().equals("FIELD_WRITE_RELAXED")));
        assertTrue(compare(old, field(b, a, null)).entries().stream()
                .anyMatch(entry -> entry.reason().equals("FIELD_PLAIN_READ_RELAXED")));
        assertFalse(compare(field(b, a, b), old).authorizationExpansion());
    }

    @Test
    void partialNeverInfersRetirement() {
        var old = manifest(List.of(api("demo.one", group(PermissionMode.ALL, "demo.a")),
                api("demo.two", group(PermissionMode.ALL, "demo.b"))), false);
        var next = manifest(List.of(api("demo.one", group(PermissionMode.ALL, "demo.a"))), true);
        var report = diff.compare(old, next, Set.of());
        assertFalse(report.absenceCompared());
        assertFalse(report.entries().stream().anyMatch(entry -> entry.kind() == PermissionManifestDiff.Kind.RETIRE));
        var full = diff.compare(old, manifest(next.resources(), false), Set.of());
        assertTrue(full.entries().stream().anyMatch(entry -> entry.kind() == PermissionManifestDiff.Kind.RETIRE && entry.key().equals("demo.two")));
    }

    @Test
    void immutablePermissionMeaningConflictIsExplicit() {
        var base = manifest(List.of(api("demo.read", group(PermissionMode.ALL, "demo.a"))), false);
        var old = withDefinition(base, "Read business records");
        var next = withDefinition(base, "Delete business records");
        assertTrue(diff.compare(old, next, Set.of()).conflicts());
    }

    private PermissionManifest withDefinition(PermissionManifest source, String meaning) {
        return new PermissionManifest(source.schemaVersion(), source.application(), source.producer(), source.artifact(),
                List.of(new PermissionManifest.PermissionDefinition("demo.a", meaning, new PermissionManifest.I18nReference("demo", "a"), DefinitionLifecycle.ACTIVE)),
                List.of("demo.b", "demo.c"), source.resources(), source.resourceReferences(), source.messages());
    }

    private PermissionManifestDiff.Result compare(PermissionManifest.ResourceDefinition old, PermissionManifest.ResourceDefinition next) {
        return diff.compare(manifest(List.of(old), false), manifest(List.of(next), false), Set.of());
    }

    private PermissionManifest.ResourceDefinition field(PermissionRequirement plain, PermissionRequirement masked, PermissionRequirement write) {
        return new PermissionManifest.ResourceDefinition("demo.email", ResourceType.FIELD, Map.of("dto", "demo.Dto", "property", "email"),
                ResourceAccess.PROTECTED, null, new PermissionManifest.FieldPolicy(PermissionManifest.JsonFieldType.STRING, plain, masked, write, "EMAIL"),
                List.of(PermissionManifest.PrincipalType.USER), List.of(), new PermissionManifest.I18nReference("demo", "email"), DefinitionLifecycle.ACTIVE);
    }

    private PermissionManifest.ResourceDefinition api(String key, PermissionRequirement requirement) {
        return new PermissionManifest.ResourceDefinition(key, ResourceType.API, Map.of("path", "/" + key), ResourceAccess.PROTECTED,
                requirement, null, List.of(PermissionManifest.PrincipalType.USER), List.of(), new PermissionManifest.I18nReference("demo", "read"), DefinitionLifecycle.ACTIVE);
    }

    private PermissionRequirement group(PermissionMode mode, String... codes) {
        return new PermissionRequirement(mode, List.of(codes));
    }

    private PermissionManifest manifest(List<PermissionManifest.ResourceDefinition> resources, boolean partial) {
        return new PermissionManifest("1.0", new PermissionManifest.Application("demo", "app"),
                new PermissionManifest.Producer("java", PermissionManifest.ProducerKind.JAVA,
                        partial ? PermissionManifest.SnapshotMode.PARTIAL : PermissionManifest.SnapshotMode.FULL,
                        List.of("demo."), List.of("api"), List.of("api"), false),
                new PermissionManifest.Artifact("demo", "a".repeat(40), "build", "1"), List.of(), List.of("demo.a", "demo.b", "demo.c"),
                resources, List.of(), List.of());
    }
}
