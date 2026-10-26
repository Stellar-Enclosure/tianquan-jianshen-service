package top.egon.cola.platform.tianquan.jianshen.starter.architecture;

import org.junit.jupiter.api.Test;

import java.nio.file.Files;
import java.nio.file.Path;
import java.util.List;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;

class StarterBoundaryTest {

    private static final List<String> FORBIDDEN_SOURCE_REFERENCES = List.of(
            "top.egon.cola.platform.tianquan.jianshen.admin",
            "top.egon.cola.platform.tianquan.jianshen.yuheng",
            "jakarta.persistence",
            "javax.sql",
            "java.sql",
            "WebClient",
            "RestClient");

    // Protocol DTO names are compared as inert manifest metadata; no Admin type is imported or loaded.
    private static final java.util.Set<String> BOOTSTRAP_PROTOCOL_METADATA = java.util.Set.of(
            "case \"tianquan-jianshen.api.manifest.plan\" -> \"top.egon.cola.platform.tianquan.jianshen.admin.registration.catalog.service.PermissionManifestPlanService.Result\";",
            "case \"tianquan-jianshen.api.manifest.register\", \"tianquan-jianshen.api.manifest.status\" -> \"top.egon.cola.platform.tianquan.jianshen.admin.registration.catalog.service.PermissionManifestRegistrationService.Result\";",
            "case \"tianquan-jianshen.api.catalog.qualify\" -> \"top.egon.cola.platform.tianquan.jianshen.admin.registration.catalog.domain.vo.DeploymentQualificationReceiptVO\";",
            "case \"tianquan-jianshen.api.catalog.versions\" -> \"top.egon.cola.platform.tianquan.jianshen.admin.registration.catalog.repository.PermissionCatalogActivationRepository.History\";");

    @Test
    void starterRemainsBusinessSideAndHasNoAdminOrDatabaseDependency()
            throws Exception {
        Path basedir = Path.of(System.getProperty("basedir"));
        Path sourceRoot = basedir.resolve("src/main/java");
        try (var files = Files.walk(sourceRoot)) {
            List<String> violations = files
                    .filter(path -> path.toString().endsWith(".java"))
                    .flatMap(path -> lines(path).stream())
                    .filter(line -> FORBIDDEN_SOURCE_REFERENCES.stream()
                            .anyMatch(line::contains))
                    .filter(line -> !BOOTSTRAP_PROTOCOL_METADATA.contains(line.strip()))
                    .toList();
            assertEquals(List.of(), violations);
        }

        String pom = Files.readString(basedir.resolve("pom.xml"));
        assertFalse(pom.contains("stellar-enclosure-tianquan-jianshen-admin"));
        assertFalse(pom.contains("stellar-enclosure-tianquan-jianshen-gateway-adapter"));
    }

    @Test
    void projectDoesNotIntroduceAnIndependentRbac3TestModule() throws Exception {
        Path platform = Path.of(System.getProperty("basedir")).getParent();
        try (var children = Files.list(platform)) {
            assertFalse(children
                    .map(path -> path.getFileName().toString())
                    .anyMatch(name -> name.matches(".*tianquan-jianshen.*-test(s)?")));
        }
    }

    private static List<String> lines(Path path) {
        try {
            return Files.readAllLines(path);
        } catch (java.io.IOException error) {
            throw new IllegalStateException(error);
        }
    }
}
