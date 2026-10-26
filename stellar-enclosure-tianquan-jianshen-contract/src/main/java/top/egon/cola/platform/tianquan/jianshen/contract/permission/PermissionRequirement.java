package top.egon.cola.platform.tianquan.jianshen.contract.permission;

import com.fasterxml.jackson.annotation.JsonInclude;

import java.util.List;
import java.util.Objects;
import java.util.Set;

/** Explicit PUBLIC, a nonempty ALL/ANY group, or a bounded conjunction of groups. */
@JsonInclude(JsonInclude.Include.NON_EMPTY)
public record PermissionRequirement(
        PermissionMode mode,
        List<String> codes,
        List<PermissionRequirement> allOf,
        ResourceAccess access
) {

    public PermissionRequirement {
        if (access != null) {
            if (access != ResourceAccess.PUBLIC || mode != null
                    || (codes != null && !codes.isEmpty()) || (allOf != null && !allOf.isEmpty())) {
                throw new IllegalArgumentException("PUBLIC cannot be combined with a permission group");
            }
            codes = List.of();
            allOf = List.of();
        } else if (allOf != null && !allOf.isEmpty()) {
            if (mode != null || (codes != null && !codes.isEmpty()) || allOf.size() > 32) {
                throw new IllegalArgumentException("allOf cannot be combined with a group");
            }
            allOf = List.copyOf(allOf);
            if (allOf.stream().anyMatch(group -> !group.allOf().isEmpty())) {
                throw new IllegalArgumentException("nested allOf is not supported");
            }
            codes = List.of();
        } else {
            mode = Objects.requireNonNull(mode, "mode");
            codes = ManifestChecks.identifiers(codes, "codes", 64, 128);
            if (codes.isEmpty()) {
                throw new IllegalArgumentException("permission groups must not be empty");
            }
            allOf = List.of();
        }
    }

    public PermissionRequirement(PermissionMode mode, List<String> codes) {
        this(mode, codes, List.of(), null);
    }

    public static PermissionRequirement allOf(List<PermissionRequirement> groups) {
        if (groups == null || groups.isEmpty()) {
            throw new IllegalArgumentException("allOf must not be empty");
        }
        return new PermissionRequirement(null, List.of(), groups, null);
    }

    public static PermissionRequirement publicAccess() {
        return new PermissionRequirement(null, List.of(), List.of(), ResourceAccess.PUBLIC);
    }

    public boolean allows(Set<String> effectiveCodes) {
        Objects.requireNonNull(effectiveCodes, "effectiveCodes");
        if (access == ResourceAccess.PUBLIC) {
            return true;
        }
        if (!allOf.isEmpty()) {
            return allOf.stream().allMatch(group -> group.allows(effectiveCodes));
        }
        return mode == PermissionMode.ALL
                ? effectiveCodes.containsAll(codes)
                : codes.stream().anyMatch(effectiveCodes::contains);
    }

    public List<PermissionRequirement> groups() {
        return allOf.isEmpty() ? List.of(this) : allOf;
    }
}
