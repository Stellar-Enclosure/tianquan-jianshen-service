package top.egon.cola.platform.tianquan.jianshen.core.registration;

import top.egon.cola.platform.tianquan.jianshen.contract.permission.PermissionManifest;
import top.egon.cola.platform.tianquan.jianshen.contract.permission.PermissionMode;
import top.egon.cola.platform.tianquan.jianshen.contract.permission.PermissionRequirement;
import top.egon.cola.platform.tianquan.jianshen.contract.permission.ResourceAccess;

import java.util.ArrayList;
import java.util.Comparator;
import java.util.HashSet;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.TreeMap;
import java.util.function.Function;

/** Candidate comparison only. A diff never mutates the active catalog or grants permissions. */
public final class PermissionManifestDiff {

    public enum Kind { ADD, CHANGE, REFERENCE, DEPRECATE, RETIRE, CONFLICT }
    public enum Domain { RESOURCE, PERMISSION, MESSAGE }

    public record Entry(Kind kind, Domain domain, String key, String reason, boolean authorizationExpansion) { }

    public record Result(List<Entry> entries, boolean authorizationExpansion, boolean conflicts, boolean absenceCompared) {
        public Result {
            entries = List.copyOf(entries);
        }
    }

    public Result compare(PermissionManifest previous, PermissionManifest candidate, Set<String> grantedCodes) {
        if (previous != null && (!previous.application().equals(candidate.application())
                || !previous.producer().id().equals(candidate.producer().id()))) {
            throw new IllegalArgumentException("diff producer/application mismatch");
        }
        List<Entry> changes = new ArrayList<>();
        boolean full = candidate.producer().snapshotMode() == PermissionManifest.SnapshotMode.FULL;
        Map<String, PermissionManifest.ResourceDefinition> resources = index(previous == null ? List.of() : previous.resources(),
                PermissionManifest.ResourceDefinition::key);
        for (PermissionManifest.ResourceDefinition next : candidate.resources()) {
            PermissionManifest.ResourceDefinition old = resources.remove(next.key());
            if (old == null) {
                boolean granted = allCodes(next).stream().anyMatch(grantedCodes::contains);
                boolean publicResource = next.access() == ResourceAccess.PUBLIC;
                boolean service = next.allowedPrincipals().contains(PermissionManifest.PrincipalType.SERVICE);
                changes.add(new Entry(Kind.ADD, Domain.RESOURCE, next.key(), publicResource ? "NEW_PUBLIC_RESOURCE"
                        : granted ? "NEW_RESOURCE_USES_GRANTED_PERMISSION" : service ? "NEW_SERVICE_RESOURCE_REQUIRES_REVIEW"
                        : "NEW_RESOURCE", publicResource || granted || service));
            } else if (old.type() != next.type()) {
                changes.add(new Entry(Kind.CONFLICT, Domain.RESOURCE, next.key(), "RESOURCE_TYPE_IS_IMMUTABLE", false));
            } else if (!old.equals(next)) {
                if (old.access() != next.access()) {
                    changes.add(new Entry(Kind.CHANGE, Domain.RESOURCE, next.key(), "ACCESS_CLASSIFICATION_CHANGED",
                            next.access() != ResourceAccess.PROTECTED));
                }
                if (!old.target().equals(next.target())) {
                    changes.add(new Entry(Kind.CHANGE, Domain.RESOURCE, next.key(), "TARGET_CHANGED_REQUIRES_REVIEW", true));
                }
                if (!old.allowedPrincipals().containsAll(next.allowedPrincipals())) {
                    changes.add(new Entry(Kind.CHANGE, Domain.RESOURCE, next.key(), "PRINCIPAL_TYPES_EXPANDED", true));
                }
                if (!next.oauthScopes().containsAll(old.oauthScopes())) {
                    changes.add(new Entry(Kind.CHANGE, Domain.RESOURCE, next.key(), "SERVICE_SCOPE_REQUIREMENTS_RELAXED", true));
                }
                if (old.requirement() != null && !implies(next.requirement(), old.requirement())) {
                    changes.add(new Entry(Kind.CHANGE, Domain.RESOURCE, next.key(), "PERMISSION_REQUIREMENTS_RELAXED", true));
                }
                compareFields(old, next, changes);
                changes.add(new Entry(next.lifecycle() != old.lifecycle() && next.lifecycle().name().equals("DEPRECATED")
                        ? Kind.DEPRECATE : Kind.CHANGE, Domain.RESOURCE, next.key(), "RESOURCE_DEFINITION_CHANGED", false));
            }
        }
        if (full) resources.keySet().forEach(key -> changes.add(new Entry(Kind.RETIRE, Domain.RESOURCE, key,
                "ABSENT_FROM_FULL_CANDIDATE", false)));

        Map<String, PermissionManifest.PermissionDefinition> definitions = index(previous == null ? List.of() : previous.permissionDefinitions(),
                PermissionManifest.PermissionDefinition::code);
        for (PermissionManifest.PermissionDefinition next : candidate.permissionDefinitions()) {
            PermissionManifest.PermissionDefinition old = definitions.remove(next.code());
            if (old == null) changes.add(new Entry(Kind.ADD, Domain.PERMISSION, next.code(), "NEW_PERMISSION_WITHOUT_ROLE_GRANT", false));
            else if (!old.meaning().equals(next.meaning())) changes.add(new Entry(Kind.CONFLICT, Domain.PERMISSION,
                    next.code(), "PERMISSION_MEANING_IS_IMMUTABLE", false));
            else if (!old.equals(next)) changes.add(new Entry(next.lifecycle() != old.lifecycle()
                    && next.lifecycle().name().equals("DEPRECATED") ? Kind.DEPRECATE : Kind.CHANGE,
                    Domain.PERMISSION, next.code(), "PERMISSION_METADATA_CHANGED", false));
        }
        if (full) definitions.keySet().forEach(code -> changes.add(new Entry(Kind.RETIRE, Domain.PERMISSION, code,
                "ABSENT_FROM_FULL_CANDIDATE", false)));
        Set<String> oldReferences = previous == null ? Set.of() : Set.copyOf(previous.permissionReferences());
        candidate.permissionReferences().stream().filter(code -> !oldReferences.contains(code)).forEach(code ->
                changes.add(new Entry(Kind.REFERENCE, Domain.PERMISSION, code, "PERMISSION_REFERENCE_ADDED", false)));
        Set<PermissionManifest.ResourceReference> oldResourceReferences = previous == null ? Set.of() : Set.copyOf(previous.resourceReferences());
        candidate.resourceReferences().stream().filter(reference -> !oldResourceReferences.contains(reference)).forEach(reference ->
                changes.add(new Entry(Kind.REFERENCE, Domain.RESOURCE, reference.key(), "RESOURCE_REFERENCE_" + reference.usage(), false)));
        Map<String, PermissionManifest.Message> messages = index(previous == null ? List.of() : previous.messages(),
                message -> message.pageCode() + '/' + message.key());
        for (PermissionManifest.Message next : candidate.messages()) {
            String key = next.pageCode() + '/' + next.key();
            PermissionManifest.Message old = messages.remove(key);
            if (!next.equals(old)) changes.add(new Entry(old == null ? Kind.ADD : Kind.CHANGE, Domain.MESSAGE, key,
                    "SOURCE_MESSAGE_CHANGED", false));
        }
        if (full) messages.keySet().forEach(key -> changes.add(new Entry(Kind.RETIRE, Domain.MESSAGE, key,
                "ABSENT_FROM_FULL_CANDIDATE", false)));
        changes.sort(Comparator.comparing((Entry value) -> value.domain().name()).thenComparing(Entry::key)
                .thenComparing(value -> value.kind().name()).thenComparing(Entry::reason));
        return new Result(changes, changes.stream().anyMatch(Entry::authorizationExpansion),
                changes.stream().anyMatch(value -> value.kind() == Kind.CONFLICT), full);
    }

    private void compareFields(PermissionManifest.ResourceDefinition old, PermissionManifest.ResourceDefinition next, List<Entry> changes) {
        if (old.fieldPolicy() == null || next.fieldPolicy() == null) return;
        PermissionManifest.FieldPolicy before = old.fieldPolicy();
        PermissionManifest.FieldPolicy after = next.fieldPolicy();
        if (before.valueType() != after.valueType()) {
            changes.add(new Entry(Kind.CONFLICT, Domain.RESOURCE, next.key(), "FIELD_VALUE_TYPE_CHANGED", false));
        }
        for (String operation : List.of("PLAIN_READ", "MASKED_READ", "WRITE")) {
            PermissionRequirement a = switch (operation) {
                case "PLAIN_READ" -> before.plainRead();
                case "MASKED_READ" -> before.maskedRead();
                default -> before.write();
            };
            PermissionRequirement b = switch (operation) {
                case "PLAIN_READ" -> after.plainRead();
                case "MASKED_READ" -> after.maskedRead();
                default -> after.write();
            };
            // Missing field operations are false; an outer absent ACCESS group adds no condition.
            if (b != null && (a == null || !fieldImplies(next.requirement(), b, old.requirement(), a))) {
                changes.add(new Entry(Kind.CHANGE, Domain.RESOURCE, next.key(), "FIELD_" + operation + "_RELAXED", true));
            }
        }
        if (after.maskedRead() != null && !java.util.Objects.equals(before.masker(), after.masker())) {
            changes.add(new Entry(Kind.CHANGE, Domain.RESOURCE, next.key(), "FIELD_MASKER_CHANGED_REQUIRES_REVIEW", true));
        }
    }

    private boolean fieldImplies(PermissionRequirement nextOuter, PermissionRequirement nextOperation,
                                 PermissionRequirement oldOuter, PermissionRequirement oldOperation) {
        List<Set<String>> candidate = new ArrayList<>(clauses(nextOperation));
        if (nextOuter != null) candidate.addAll(clauses(nextOuter));
        List<Set<String>> required = new ArrayList<>(clauses(oldOperation));
        if (oldOuter != null) required.addAll(clauses(oldOuter));
        return required.stream().allMatch(clause -> candidate.stream().anyMatch(clause::containsAll));
    }

    /** Monotone CNF implication: each required clause needs a narrower clause in the candidate. */
    boolean implies(PermissionRequirement candidate, PermissionRequirement required) {
        if (required == null || required.access() == ResourceAccess.PUBLIC) return true;
        List<Set<String>> a = candidate == null ? List.of() : clauses(candidate);
        return clauses(required).stream().allMatch(clause -> a.stream().anyMatch(clause::containsAll));
    }

    private List<Set<String>> clauses(PermissionRequirement requirement) {
        List<Set<String>> clauses = new ArrayList<>();
        for (PermissionRequirement group : requirement.groups()) {
            if (group.access() == ResourceAccess.PUBLIC) continue;
            if (group.mode() == PermissionMode.ALL) group.codes().forEach(code -> clauses.add(Set.of(code)));
            else clauses.add(Set.copyOf(group.codes()));
        }
        return clauses;
    }

    private Set<String> allCodes(PermissionManifest.ResourceDefinition resource) {
        Set<String> codes = new HashSet<>();
        List<PermissionRequirement> requirements = new ArrayList<>();
        if (resource.requirement() != null) requirements.add(resource.requirement());
        if (resource.fieldPolicy() != null) {
            for (PermissionRequirement group : new PermissionRequirement[]{resource.fieldPolicy().plainRead(),
                    resource.fieldPolicy().maskedRead(), resource.fieldPolicy().write()}) {
                if (group != null) requirements.add(group);
            }
        }
        requirements.forEach(requirement -> requirement.groups().forEach(group -> codes.addAll(group.codes())));
        return codes;
    }

    private <T> Map<String, T> index(List<T> values, Function<T, String> key) {
        Map<String, T> result = new TreeMap<>();
        values.forEach(value -> result.put(key.apply(value), value));
        return result;
    }
}
