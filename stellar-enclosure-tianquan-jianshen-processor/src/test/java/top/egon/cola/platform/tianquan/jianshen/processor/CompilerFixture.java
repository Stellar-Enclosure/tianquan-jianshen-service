package top.egon.cola.platform.tianquan.jianshen.processor;

import com.fasterxml.jackson.core.type.TypeReference;
import com.fasterxml.jackson.databind.ObjectMapper;
import top.egon.cola.platform.tianquan.jianshen.contract.permission.PermissionManifest;
import top.egon.cola.platform.tianquan.jianshen.contract.permission.PermissionManifestReader;

import javax.tools.DiagnosticCollector;
import javax.tools.JavaFileObject;
import javax.tools.ToolProvider;
import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.ArrayList;
import java.util.List;
import java.util.Map;
import java.util.TreeMap;

final class CompilerFixture {

    static final String IMPORTS = """
            package demo;
            import top.egon.cola.platform.tianquan.jianshen.contract.permission.*;
            import top.egon.cola.platform.tianquan.jianshen.contract.permission.annotation.*;
            import org.springframework.web.bind.annotation.*;
            import java.lang.annotation.*;
            """;

    record Result(boolean success, String diagnostics, Path output) {
        Path fragmentPath() {
            return output.resolve(PermissionManifestProcessor.FRAGMENT);
        }

        PermissionManifest manifest() throws IOException {
            return new PermissionManifestReader().read(new ObjectMapper().readValue(
                    Files.readString(fragmentPath()), new TypeReference<Map<String, Object>>() { }));
        }
    }

    static Result compile(Path directory, String source) throws IOException {
        return compile(directory, source, Map.of());
    }

    static Result compile(Path directory, String source, Map<String, String> overrides) throws IOException {
        Map<String, String> sources = new TreeMap<>();
        sources.put("demo/Example.java", IMPORTS + source);
        sources.put("org/springframework/stereotype/Component.java", """
                package org.springframework.stereotype;
                import java.lang.annotation.*;
                @Target({ElementType.TYPE,ElementType.ANNOTATION_TYPE}) @Retention(RetentionPolicy.RUNTIME)
                public @interface Component {}
                """);
        sources.put("org/springframework/stereotype/Controller.java", """
                package org.springframework.stereotype;
                import java.lang.annotation.*;
                @Target({ElementType.TYPE,ElementType.ANNOTATION_TYPE}) @Retention(RetentionPolicy.RUNTIME)
                @Component public @interface Controller {}
                """);
        sources.put("org/springframework/web/bind/annotation/RestController.java", """
                package org.springframework.web.bind.annotation;
                import java.lang.annotation.*;
                @org.springframework.stereotype.Controller
                @Target(ElementType.TYPE) @Retention(RetentionPolicy.RUNTIME)
                public @interface RestController {}
                """);
        sources.put("org/springframework/web/bind/annotation/RequestMethod.java", """
                package org.springframework.web.bind.annotation;
                public enum RequestMethod {GET,HEAD,POST,PUT,PATCH,DELETE,OPTIONS,TRACE}
                """);
        sources.put("org/springframework/web/bind/annotation/RequestMapping.java", """
                package org.springframework.web.bind.annotation;
                import java.lang.annotation.*;
                @Target({ElementType.TYPE,ElementType.METHOD,ElementType.ANNOTATION_TYPE}) @Retention(RetentionPolicy.RUNTIME)
                public @interface RequestMapping {
                  String[] value() default {}; String[] path() default {}; RequestMethod[] method() default {};
                  String[] params() default {}; String[] headers() default {};
                  String[] consumes() default {}; String[] produces() default {}; String name() default ""; String version() default "";
                }
                """);
        sources.put("org/springframework/web/bind/annotation/GetMapping.java", """
                package org.springframework.web.bind.annotation;
                import java.lang.annotation.*;
                @RequestMapping(method=RequestMethod.GET)
                @Target({ElementType.METHOD,ElementType.ANNOTATION_TYPE}) @Retention(RetentionPolicy.RUNTIME)
                public @interface GetMapping {
                  String[] value() default {}; String[] path() default {};
                  String[] params() default {}; String[] headers() default {};
                  String[] consumes() default {}; String[] produces() default {}; String name() default ""; String version() default "";
                }
                """);
        sources.put("org/springframework/core/annotation/AliasFor.java", """
                package org.springframework.core.annotation;
                import java.lang.annotation.*;
                @Target(ElementType.METHOD) @Retention(RetentionPolicy.RUNTIME)
                public @interface AliasFor {
                  String value() default ""; String attribute() default "";
                  Class<? extends Annotation> annotation() default Annotation.class;
                }
                """);
        List<Path> files = new ArrayList<>();
        for (Map.Entry<String, String> entry : sources.entrySet()) {
            Path path = directory.resolve("src").resolve(entry.getKey());
            Files.createDirectories(path.getParent());
            Files.writeString(path, entry.getValue());
            files.add(path);
        }
        Path output = directory.resolve("classes");
        Files.createDirectories(output);
        var compiler = ToolProvider.getSystemJavaCompiler();
        DiagnosticCollector<JavaFileObject> diagnostics = new DiagnosticCollector<>();
        try (var manager = compiler.getStandardFileManager(diagnostics, null, StandardCharsets.UTF_8)) {
            List<String> options = new ArrayList<>(List.of("-d", output.toString(), "-classpath",
                    System.getProperty("surefire.test.class.path", System.getProperty("java.class.path")), "-proc:full"));
            Map<String, String> config = new TreeMap<>(Map.ofEntries(
                    Map.entry("business", "test"), Map.entry("application", "demo"), Map.entry("producer", "demo-java"),
                    Map.entry("module", "api"), Map.entry("expectedModules", "api"), Map.entry("ownedKeyPrefixes", "demo."),
                    Map.entry("managedPackages", "demo"), Map.entry("repository", "demo-repository"),
                    Map.entry("commit", "a".repeat(40)), Map.entry("buildId", "test-build"), Map.entry("version", "1")));
            config.putAll(overrides);
            config.forEach((key, value) -> options.add("-Apac." + key + "=" + value));
            var task = compiler.getTask(null, manager, diagnostics, options, null, manager.getJavaFileObjectsFromPaths(files));
            task.setProcessors(List.of(new PermissionManifestProcessor()));
            boolean success = task.call();
            return new Result(success, diagnostics.getDiagnostics().toString(), output);
        }
    }
}
