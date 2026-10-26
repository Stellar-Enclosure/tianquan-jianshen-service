package top.egon.cola.platform.tianquan.jianshen.processor;

import javax.lang.model.element.AnnotationMirror;
import javax.lang.model.element.AnnotationValue;
import javax.lang.model.element.Element;
import javax.lang.model.element.TypeElement;
import javax.lang.model.util.Elements;
import java.util.ArrayList;
import java.util.HashSet;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.TreeMap;

/** Reads constants and meta-annotations through javac without loading producer classes. */
final class CompilerAnnotations {

    static final String CONTRACT = "top.egon.cola.platform.tianquan.jianshen.contract.permission.annotation.";
    private final Elements elements;

    CompilerAnnotations(Elements elements) {
        this.elements = elements;
    }

    String name(AnnotationMirror annotation) {
        return ((TypeElement) annotation.getAnnotationType().asElement()).getQualifiedName().toString();
    }

    Map<String, AnnotationValue> values(AnnotationMirror annotation) {
        Map<String, AnnotationValue> result = new TreeMap<>();
        elements.getElementValuesWithDefaults(annotation)
                .forEach((key, value) -> result.put(key.getSimpleName().toString(), value));
        return result;
    }

    String text(AnnotationMirror annotation, String key) {
        AnnotationValue value = values(annotation).get(key);
        if (value == null || !(value.getValue() instanceof String text)) {
            throw new IllegalArgumentException("expected a constant string for " + key);
        }
        return text;
    }

    String enumeration(AnnotationMirror annotation, String key) {
        Object value = values(annotation).get(key).getValue();
        if (!(value instanceof Element element)) {
            throw new IllegalArgumentException("expected an enum for " + key);
        }
        return element.getSimpleName().toString();
    }

    List<AnnotationValue> array(AnnotationMirror annotation, String key) {
        Object value = values(annotation).get(key).getValue();
        if (!(value instanceof List<?> entries)) {
            throw new IllegalArgumentException("expected a constant array for " + key);
        }
        List<AnnotationValue> result = new ArrayList<>();
        for (Object entry : entries) result.add((AnnotationValue) entry);
        return result;
    }

    List<String> strings(AnnotationMirror annotation, String key) {
        return array(annotation, key).stream().map(value -> {
            if (!(value.getValue() instanceof String text)) {
                throw new IllegalArgumentException("expected constant strings for " + key);
            }
            return text;
        }).toList();
    }

    AnnotationMirror nested(AnnotationMirror annotation, String key) {
        return (AnnotationMirror) values(annotation).get(key).getValue();
    }

    List<AnnotationMirror> find(Element element, String simpleName) {
        List<AnnotationMirror> result = new ArrayList<>();
        for (AnnotationMirror annotation : element.getAnnotationMirrors()) {
            collect(annotation, CONTRACT + simpleName, new HashSet<>(), result);
        }
        return result;
    }

    private void collect(AnnotationMirror annotation, String wanted, Set<String> visiting,
                         List<AnnotationMirror> result) {
        String name = name(annotation);
        if (name.equals(wanted)) {
            result.add(annotation);
            return;
        }
        if (name.startsWith("java.lang.annotation.") || !visiting.add(name)) return;
        if (Set.of(CONTRACT + "PermissionGroups", CONTRACT + "PermissionDefinitions",
                CONTRACT + "PermissionMessages").contains(name)) {
            for (AnnotationValue value : array(annotation, "value")) {
                collect((AnnotationMirror) value.getValue(), wanted, visiting, result);
            }
        } else {
            for (AnnotationMirror meta : annotation.getAnnotationType().asElement().getAnnotationMirrors()) {
                collect(meta, wanted, visiting, result);
            }
        }
        visiting.remove(name);
    }

    boolean hasAnnotation(Element element, String qualifiedName) {
        return element.getAnnotationMirrors().stream().anyMatch(annotation ->
                hasAnnotation(annotation, qualifiedName, new HashSet<>()));
    }

    private boolean hasAnnotation(AnnotationMirror annotation, String wanted, Set<String> visiting) {
        String name = name(annotation);
        if (name.equals(wanted)) return true;
        if (name.startsWith("java.lang.annotation.") || !visiting.add(name)) return false;
        boolean found = annotation.getAnnotationType().asElement().getAnnotationMirrors().stream()
                .anyMatch(meta -> hasAnnotation(meta, wanted, visiting));
        visiting.remove(name);
        return found;
    }

    AnnotationMirror unique(List<? extends Element> sources, String annotationName) {
        List<AnnotationMirror> found = sources.stream().flatMap(source -> find(source, annotationName).stream())
                .toList();
        if (found.isEmpty()) return null;
        String first = values(found.getFirst()).toString();
        if (found.stream().anyMatch(annotation -> !values(annotation).toString().equals(first))) {
            throw new IllegalArgumentException("conflicting " + annotationName + " declarations in hierarchy");
        }
        return found.getFirst();
    }
}
