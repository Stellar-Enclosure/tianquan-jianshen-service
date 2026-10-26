package top.egon.cola.platform.tianquan.jianshen.processor;

import javax.lang.model.element.AnnotationMirror;
import javax.lang.model.element.AnnotationValue;
import javax.lang.model.element.Element;
import javax.lang.model.element.ExecutableElement;
import javax.lang.model.util.ElementFilter;
import java.util.ArrayList;
import java.util.HashSet;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.TreeMap;
import java.util.TreeSet;

/** Resolves the supported Spring mapping model; unsupported aliases fail the compilation. */
final class SpringMappingResolver {

    private static final String SPRING = "org.springframework.web.bind.annotation.";
    private static final Set<String> ATTRIBUTES = Set.of("path", "method", "params", "headers", "consumes", "produces", "version");
    private static final List<String> ALL_METHODS = List.of("DELETE", "GET", "HEAD", "PATCH", "POST", "PUT", "TRACE");
    private final CompilerAnnotations annotations;

    SpringMappingResolver(CompilerAnnotations annotations) {
        this.annotations = annotations;
    }

    Map<String, List<String>> resolve(List<? extends Element> sources) {
        List<Map<String, List<String>>> found = new ArrayList<>();
        for (Element source : sources) {
            for (AnnotationMirror annotation : source.getAnnotationMirrors()) {
                Map<String, List<String>> mapping = resolve(annotation, new HashSet<>());
                if (mapping != null) found.add(mapping);
            }
        }
        if (found.isEmpty()) return null;
        if (found.stream().anyMatch(value -> !value.equals(found.getFirst()))) {
            throw new IllegalArgumentException("ambiguous Spring mappings in type or method hierarchy");
        }
        return found.getFirst();
    }

    private Map<String, List<String>> resolve(AnnotationMirror annotation, Set<String> visiting) {
        String name = annotations.name(annotation);
        if (name.startsWith("java.lang.annotation.") || !visiting.add(name)) return null;
        Map<String, List<String>> mapping = null;
        if (name.equals(SPRING + "RequestMapping")) {
            mapping = new TreeMap<>();
            for (String attribute : ATTRIBUTES) {
                mapping.put(attribute, values(annotation, attribute));
            }
            applyPathAlias(mapping, values(annotation, "value"));
        } else {
            List<Map<String, List<String>>> parents = new ArrayList<>();
            for (AnnotationMirror meta : annotation.getAnnotationType().asElement().getAnnotationMirrors()) {
                Map<String, List<String>> candidate = resolve(meta, visiting);
                if (candidate != null) parents.add(candidate);
            }
            if (!parents.isEmpty()) {
                if (parents.size() != 1) throw new IllegalArgumentException("multiple composed Spring mappings");
                mapping = new TreeMap<>(parents.getFirst());
                Map<String, List<String>> overrides = new TreeMap<>();
                for (ExecutableElement attribute : ElementFilter.methodsIn(
                        annotation.getAnnotationType().asElement().getEnclosedElements())) {
                    String attributeName = attribute.getSimpleName().toString();
                    if (attributeName.equals("name")) continue;
                    List<String> override = values(annotation, attributeName);
                    if (override.isEmpty()) continue;
                    String destination = name.startsWith(SPRING) ? attributeName : alias(attribute);
                    if (destination == null) {
                        throw new IllegalArgumentException("unresolved composed mapping attribute " + attributeName);
                    }
                    if (destination.equals("value")) destination = "path";
                    if (!ATTRIBUTES.contains(destination)) {
                        throw new IllegalArgumentException("unsupported mapping alias " + destination);
                    }
                    List<String> previous = overrides.putIfAbsent(destination, override);
                    if (previous != null && !previous.equals(override)) {
                        throw new IllegalArgumentException("conflicting mapping aliases");
                    }
                }
                mapping.putAll(overrides);
            }
        }
        visiting.remove(name);
        return mapping;
    }

    private String alias(ExecutableElement attribute) {
        for (AnnotationMirror annotation : attribute.getAnnotationMirrors()) {
            if (!annotations.name(annotation).equals("org.springframework.core.annotation.AliasFor")) continue;
            Map<String, AnnotationValue> values = annotations.values(annotation);
            String target = values.containsKey("annotation") ? values.get("annotation").getValue().toString() : "";
            if (!target.startsWith(SPRING)) {
                throw new IllegalArgumentException("mapping aliases must resolve directly to a Spring mapping");
            }
            String explicit = annotations.text(annotation, "attribute");
            String shorthand = annotations.text(annotation, "value");
            if (!explicit.isEmpty() && !shorthand.isEmpty() && !explicit.equals(shorthand)) {
                throw new IllegalArgumentException("conflicting AliasFor values");
            }
            return !explicit.isEmpty() ? explicit : !shorthand.isEmpty() ? shorthand : attribute.getSimpleName().toString();
        }
        return null;
    }

    private List<String> values(AnnotationMirror annotation, String attribute) {
        AnnotationValue value = annotations.values(annotation).get(attribute);
        if (value == null) return List.of();
        Object raw = value.getValue();
        List<?> entries = raw instanceof List<?> list ? list : List.of(value);
        TreeSet<String> result = new TreeSet<>();
        for (Object entry : entries) {
            Object constant = ((AnnotationValue) entry).getValue();
            String text;
            if (constant instanceof String string) text = string;
            else if (constant instanceof Element element) text = element.getSimpleName().toString();
            else throw new IllegalArgumentException("mapping attribute is not a supported constant");
            if (text.contains("${") || text.contains("#{")) {
                throw new IllegalArgumentException("dynamic Spring mappings cannot be exported");
            }
            if (attribute.equals("version") && text.isEmpty()) continue;
            result.add(text);
        }
        return List.copyOf(result);
    }

    private void applyPathAlias(Map<String, List<String>> mapping, List<String> value) {
        if (value.isEmpty()) return;
        if (!mapping.get("path").isEmpty() && !mapping.get("path").equals(value)) {
            throw new IllegalArgumentException("conflicting RequestMapping path/value aliases");
        }
        mapping.put("path", value);
    }

    Map<String, Object> target(Map<String, List<String>> type, Map<String, List<String>> method) {
        return target(type, method, true);
    }

    Map<String, Object> target(Map<String, List<String>> type, Map<String, List<String>> method, boolean mvcSemantics) {
        Map<String, List<String>> base = type == null ? Map.of() : type;
        Map<String, Object> result = new TreeMap<>();
        TreeSet<String> paths = new TreeSet<>();
        List<String> prefixes = base.getOrDefault("path", List.of());
        if (prefixes.isEmpty()) prefixes = List.of("");
        List<String> suffixes = method.get("path");
        if (suffixes.isEmpty()) suffixes = List.of("");
        for (String prefix : prefixes) for (String suffix : suffixes) {
            // Pattern combination has more semantics than concatenation; reject unsupported cases.
            if (prefix.contains("*") || prefix.contains("{*")) {
                throw new IllegalArgumentException("wildcard class mappings need an explicit resolvable API mapping");
            }
            if (prefix.isEmpty() && suffix.isEmpty()) {
                throw new IllegalArgumentException("empty root mapping requires an explicit '/' path");
            }
            String path = suffix.isEmpty() ? prefix
                    : prefix + (prefix.endsWith("/") || suffix.startsWith("/") ? "" : "/") + suffix;
            if (prefix.endsWith("/") && suffix.startsWith("/")) path = prefix + suffix.substring(1);
            if (!path.startsWith("/")) path = "/" + path;
            paths.add(path);
        }
        result.put("paths", List.copyOf(paths));
        List<String> parentMethods = base.getOrDefault("method", List.of());
        List<String> childMethods = method.get("method");
        TreeSet<String> methods = new TreeSet<>(parentMethods);
        methods.addAll(childMethods);
        if (methods.isEmpty() && !mvcSemantics) {
            throw new IllegalArgumentException("metadata-only protocol mapping requires explicit HTTP methods");
        }
        if (methods.isEmpty()) methods.addAll(ALL_METHODS);
        if (mvcSemantics && methods.contains("GET")) methods.add("HEAD");
        result.put("methods", List.copyOf(methods));
        for (String attribute : List.of("params", "headers", "consumes", "produces")) {
            TreeSet<String> constraints = new TreeSet<>(base.getOrDefault(attribute, List.of()));
            if ((attribute.equals("consumes") || attribute.equals("produces")) && !method.get(attribute).isEmpty()) {
                constraints.clear();
            }
            constraints.addAll(method.get(attribute));
            if (!constraints.isEmpty()) result.put(attribute, List.copyOf(constraints));
        }
        List<String> versions = method.get("version").isEmpty() ? base.getOrDefault("version", List.of()) : method.get("version");
        if (!versions.isEmpty()) result.put("version", versions.getFirst());
        return result;
    }
}
