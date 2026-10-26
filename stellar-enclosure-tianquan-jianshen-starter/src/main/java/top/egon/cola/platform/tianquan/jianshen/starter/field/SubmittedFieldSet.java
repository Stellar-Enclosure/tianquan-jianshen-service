package top.egon.cola.platform.tianquan.jianshen.starter.field;

import java.util.LinkedHashSet;
import java.util.Set;

/** Exact property presence from the transport binder, including explicit nulls and array paths. */
public record SubmittedFieldSet(Set<String> paths) {
    public SubmittedFieldSet {
        if (paths == null || paths.size() > 10_000) throw new IllegalArgumentException("submitted fields exceed limit");
        var values = new LinkedHashSet<String>();
        for (String path : paths) {
            if (path == null || path.isBlank() || path.length() > 2048) throw new IllegalArgumentException("submitted field path is invalid");
            values.add(path);
        }
        paths = Set.copyOf(values);
    }

    public static SubmittedFieldSet capture(com.fasterxml.jackson.databind.JsonNode body) {
        var paths = new LinkedHashSet<String>();
        capture(body, "", paths, 0);
        return new SubmittedFieldSet(paths);
    }

    private static void capture(com.fasterxml.jackson.databind.JsonNode node, String prefix, Set<String> paths, int depth) {
        if (depth > 64 || paths.size() > 10_000) throw new IllegalArgumentException("submitted structure exceeds limit");
        if (node.isObject()) {
            node.fields().forEachRemaining(entry -> {
                String path = prefix.isEmpty() ? entry.getKey() : prefix + "." + entry.getKey();
                paths.add(path);
                capture(entry.getValue(), path, paths, depth + 1);
            });
        } else if (node.isArray()) {
            for (int index = 0; index < node.size(); index++) capture(node.get(index), prefix + "[" + index + "]", paths, depth + 1);
        }
    }
}
