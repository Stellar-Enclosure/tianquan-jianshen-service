package top.egon.cola.platform.tianquan.jianshen.admin.integration;

import com.fasterxml.jackson.annotation.JsonInclude;
import top.egon.cola.platform.tianquan.jianshen.admin.iam.application.domain.vo.ApplicationAuthorizationScopeVO;
import top.egon.cola.platform.tianquan.jianshen.admin.iam.business.domain.vo.BusinessCatalogEntry;
import top.egon.cola.platform.tianquan.jianshen.admin.iam.business.domain.vo.ApplicationCatalogEntry;

import com.fasterxml.jackson.core.JsonParser;
import com.fasterxml.jackson.databind.DeserializationFeature;
import com.fasterxml.jackson.databind.MapperFeature;
import com.fasterxml.jackson.databind.ObjectMapper;
import top.egon.cola.platform.tianquan.jianshen.admin.authorization.resource.service.GlobalResourceCatalogService;
import top.egon.cola.platform.tianquan.jianshen.admin.authorization.policy.management.service.ManagementPolicyFacade;
import top.egon.cola.platform.tianquan.jianshen.admin.authorization.policy.management.domain.dto.SaveCommandDTO;
import top.egon.cola.platform.tianquan.jianshen.admin.authorization.policy.management.domain.vo.PolicyVO;
import top.egon.cola.platform.tianquan.jianshen.admin.authorization.policy.management.domain.vo.ManagementPolicyRestrictionsVO;
import top.egon.cola.platform.tianquan.jianshen.admin.authorization.policy.management.domain.vo.ManagementPolicySubjectVO;
import top.egon.cola.platform.tianquan.jianshen.admin.authorization.policy.management.domain.vo.ManagementPolicyScopeVO;
import top.egon.cola.platform.tianquan.jianshen.admin.authorization.grant.userrole.domain.dto.RoleAssignmentDTO;
import top.egon.cola.platform.tianquan.jianshen.admin.authorization.grant.userrole.domain.vo.AssignmentVO;
import top.egon.cola.platform.tianquan.jianshen.admin.authorization.grant.userrole.domain.vo.AssignmentResultVO;
import top.egon.cola.platform.tianquan.jianshen.admin.authorization.grant.business.domain.vo.UserBusinessAccessVO;

import top.egon.cola.platform.tianquan.jianshen.admin.authorization.grant.userrole.service.AssignmentFacade;
import top.egon.cola.platform.tianquan.jianshen.admin.iam.user.service.UserCrudFacade;
import top.egon.cola.platform.tianquan.jianshen.admin.iam.user.domain.dto.CreateUserCommandDTO;
import top.egon.cola.platform.tianquan.jianshen.admin.iam.user.domain.enums.UserStatusEnum;
import top.egon.cola.platform.tianquan.jianshen.admin.authorization.resource.domain.command.DeploymentCatalogRegistrationCommand;
import top.egon.cola.platform.tianquan.jianshen.admin.authorization.permission.domain.vo.PermissionCatalogVO;
import top.egon.cola.platform.tianquan.jianshen.admin.authorization.resource.domain.vo.ResourceVO;
import top.egon.cola.platform.tianquan.jianshen.admin.authorization.resource.domain.vo.DeploymentCatalogRegistrationResultVO;
import top.egon.cola.platform.tianquan.jianshen.admin.authorization.resource.field.domain.vo.FieldDefinitionVO;
import top.egon.cola.platform.tianquan.jianshen.admin.iam.role.domain.vo.RoleVO;
import top.egon.cola.platform.tianquan.jianshen.contract.authorization.FieldAccessLevel;
import jakarta.validation.Valid;
import jakarta.validation.Validation;
import jakarta.validation.Validator;
import jakarta.validation.constraints.Max;
import jakarta.validation.constraints.Min;
import jakarta.validation.constraints.NotBlank;
import jakarta.validation.constraints.NotNull;
import jakarta.validation.constraints.Pattern;
import jakarta.validation.constraints.Size;
import jakarta.validation.groups.Default;
import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Data;
import lombok.NoArgsConstructor;
import lombok.experimental.Accessors;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;
import org.springframework.http.converter.json.Jackson2ObjectMapperBuilder;

import jakarta.persistence.EntityManager;
import org.redisson.api.RedissonClient;
import org.redisson.client.codec.StringCodec;
import org.mockito.Mockito;
import org.mockito.ArgumentMatchers;
import top.egon.cola.platform.tianquan.jianshen.admin.iam.user.domain.vo.UserDirectoryVO;
import org.springframework.context.annotation.AnnotationConfigApplicationContext;
import org.springframework.jdbc.datasource.AbstractDataSource;
import org.springframework.jdbc.datasource.DriverManagerDataSource;
import top.egon.cola.component.common.core.validation.ValidationUtils;
import top.egon.cola.platform.tianquan.jianshen.admin.shared.domain.DatabaseClock;

import javax.sql.DataSource;
import java.nio.ByteBuffer;
import java.nio.CharBuffer;
import java.nio.charset.CharacterCodingException;
import java.nio.charset.StandardCharsets;
import java.time.Duration;
import java.util.Arrays;
import java.util.LinkedHashMap;

import top.egon.cola.platform.tianquan.jianshen.admin.authorization.grant.application.service.TenantApplicationFacade;
import top.egon.cola.platform.tianquan.jianshen.admin.authorization.grant.business.service.UserBusinessAccessFacade;
import top.egon.cola.platform.tianquan.jianshen.admin.bootstrap.domain.Rbac3DevelopmentTopology;
import top.egon.cola.platform.tianquan.jianshen.admin.iam.user.domain.po.UserPO;
import top.egon.cola.platform.tianquan.jianshen.admin.iam.role.domain.po.RolePO;
import top.egon.cola.platform.tianquan.jianshen.admin.authorization.grant.business.domain.command.ReplaceUserBusinessAccessesCommand;
import top.egon.cola.platform.tianquan.jianshen.admin.authorization.grant.business.domain.enums.UserBusinessAccessStatusEnum;
import top.egon.cola.platform.tianquan.jianshen.admin.authorization.runtime.activation.domain.dto.ReplaceCommandDTO;
import top.egon.cola.platform.tianquan.jianshen.admin.authorization.runtime.state.repository.TenantAuthorizationStateRepository;
import java.time.Instant;
import java.nio.channels.FileChannel;
import java.nio.file.StandardCopyOption;
import org.slf4j.MDC;
import top.egon.cola.platform.tianquan.jianshen.admin.bootstrap.domain.dto.ResolvedPlatformBootstrapCommandDTO;
import top.egon.cola.platform.tianquan.jianshen.admin.bootstrap.domain.dto.ResolvedPlatformBootstrapCommandDTO.PlatformCatalogBindingDTO;
import top.egon.cola.platform.tianquan.jianshen.admin.iam.user.repository.IdentityProfileDirectory;
import top.egon.cola.platform.tianquan.jianshen.admin.authorization.runtime.activation.service.RoleActivationFacade;
import top.egon.cola.platform.tianquan.jianshen.admin.authorization.runtime.service.UserAuthorizationSnapshotProjector;
import top.egon.cola.platform.tianquan.jianshen.admin.authorization.runtime.repository.postgresql.PostgresqlAuthorizationRuntimeRepository;
import top.egon.cola.platform.tianquan.jianshen.admin.iam.business.repository.DdcCatalogGateway;

import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.LinkOption;
import java.nio.file.Path;
import java.nio.file.StandardOpenOption;
import java.nio.file.attribute.BasicFileAttributes;
import java.nio.file.attribute.PosixFilePermissions;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.sql.Connection;
import java.sql.SQLException;
import java.util.HashSet;
import java.util.HexFormat;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.Objects;
import java.util.UUID;
import java.util.concurrent.atomic.AtomicInteger;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

/** Independent JA target boundary; ordinary tests never create a live Spring context. */
public class IsolatedAuthorizationProvisioningIT {
    private static final java.time.Duration NATIVE_POLICY_LIFETIME = java.time.Duration.ofMinutes(10);
    private static final java.time.Duration NATIVE_ASSIGNMENT_LIFETIME = java.time.Duration.ofHours(8);

    @TempDir
    Path temporaryRepository;

    @BeforeEach
    void canonicalRepository() throws IOException {
        temporaryRepository = temporaryRepository.toRealPath();
    }

    public interface Prepare { }
    public interface Provision { }
    public interface Runtime { }

    static final Map<String, String> DATABASE_NAMES = Map.of(
            "idp", "xingyuan_it_idp_20261011", "rbac", "xingyuan_it_rbac_20261011",
            "tianshu", "xingyuan_it_tianshu_20261011", "yuheng", "xingyuan_it_yuheng_20261011",
            "llm", "xingyuan_it_llm_20261011", "light", "xingyuan_it_light_20261011",
            "web", "xingyuan_it_web_20261011", "service", "xingyuan_it_service_20261011",
            "agent", "xingyuan_it_agent_20261011");

    static DataSource guardPhysicalDataSource(DataSource physicalDataSource,
                                                        IsolatedDatabaseReceiptDTO receipt) {
        return new GuardedPhysicalDataSource(physicalDataSource, receipt);
    }

    static DataSource physicalDataSource(VerifiedDatabaseInputsBO inputs) throws IOException {
        validateDatabaseReceipt(inputs.getManifest(), inputs.getManifestSha256(), "rbac", inputs.getReceipt());
        String expectedUrl = "jdbc:postgresql://127.0.0.1:5432/" + DATABASE_NAMES.get("rbac");
        if (!expectedUrl.equals(inputs.getJdbcUrl())) {
            throw new IllegalArgumentException("XINGYUAN_TARGET_UNSAFE");
        }
        char[] credential = readProtectedCharacters(Path.of(inputs.getManifest().getPostgres().getCredentialFile()),
                null, 4096);
        try {
            if (credential.length == 0) {
                throw new IllegalArgumentException("XINGYUAN_INPUT_INVALID");
            }
            var source = new DriverManagerDataSource(
                    expectedUrl + "?connectTimeout=5&socketTimeout=30", inputs.getReceipt().getDatabaseOwner(),
                    new String(credential));
            return guardPhysicalDataSource(source, inputs.getReceipt());
        } finally {
            Arrays.fill(credential, '\0');
        }
    }

    static char[] readProtectedCharacters(Path file, Path taskRoot, int maximumBytes) throws IOException {
        byte[] bytes = readProtectedBytes(file, taskRoot, maximumBytes);
        CharBuffer decoded = null;
        try {
            decoded = StandardCharsets.UTF_8.newDecoder().decode(ByteBuffer.wrap(bytes));
            int length = decoded.remaining();
            // A file may end with one line terminator; spaces and embedded newlines remain part of the credential.
            if (length > 0 && decoded.get(length - 1) == '\n') {
                length--;
                if (length > 0 && decoded.get(length - 1) == '\r') {
                    length--;
                }
            }
            char[] characters = new char[length];
            decoded.get(characters, 0, length);
            return characters;
        } catch (CharacterCodingException invalidEncoding) {
            throw new IllegalArgumentException("XINGYUAN_INPUT_INVALID");
        } finally {
            Arrays.fill(bytes, (byte) 0);
            if (decoded != null) {
                decoded.clear();
                for (int index = 0; index < decoded.capacity(); index++) {
                    decoded.put(index, '\0');
                }
            }
        }
    }

    @lombok.RequiredArgsConstructor
    public static class GuardedPhysicalDataSource extends AbstractDataSource {
        private final DataSource delegate;
        private final IsolatedDatabaseReceiptDTO receipt;


        // ShardingSphere inspects JavaBean connection properties before using the guarded connections.
        public String getUrl() {
            return delegate instanceof DriverManagerDataSource source ? source.getUrl() : null;
        }

        public String getUsername() {
            return delegate instanceof DriverManagerDataSource source ? source.getUsername() : null;
        }

        public String getPassword() {
            return delegate instanceof DriverManagerDataSource source ? source.getPassword() : null;
        }

        @Override
        public Connection getConnection() throws SQLException {
            var connection = delegate.getConnection();
            try {
                verifyDatabaseConnection(connection, receipt);
                return connection;
            } catch (SQLException | RuntimeException rejected) {
                try {
                    connection.close();
                } catch (SQLException closeFailure) {
                    rejected.addSuppressed(closeFailure);
                }
                throw rejected;
            }
        }

        @Override
        public Connection getConnection(String username, String password) {
            throw new IllegalArgumentException("XINGYUAN_TARGET_UNSAFE");
        }
    }









    private static List<String> provisioningDirectorySubjects(com.fasterxml.jackson.databind.JsonNode registry) {
        var interactive = registry.path("subjects");
        if (!interactive.isObject() || interactive.size() != 2 || !interactive.has("admin") || !interactive.has("viewer")) {
            throw new IllegalArgumentException("XINGYUAN_TARGET_UNSAFE");
        }
        String provisioner = requiredJsonText(registry, "provisioningSubject", 128);
        var subjects = List.of(requiredJsonText(interactive, "admin", 128), requiredJsonText(interactive, "viewer", 128), provisioner);
        if (!provisioner.matches("[A-Za-z0-9._:-]{1,128}") || new HashSet<>(subjects).size() != 3) { throw new IllegalArgumentException("XINGYUAN_TARGET_UNSAFE"); }
        return subjects;
    }

    @Test
    void provisioningSubjectsRequireASeparateDirectoryIdentity() {
        var registry = strictMapper().createObjectNode();
        registry.putObject("subjects").put("admin", "101").put("viewer", "102"); registry.put("provisioningSubject", "103");
        assertThat(provisioningDirectorySubjects(registry)).containsExactly("101", "102", "103");
        for (String invalid : List.of("101", "102", "bad\nsubject")) {
            var wrong = registry.deepCopy().put("provisioningSubject", invalid);
            assertThatThrownBy(() -> provisioningDirectorySubjects(wrong)).hasMessage("XINGYUAN_TARGET_UNSAFE");
        }
        var missing = registry.deepCopy(); missing.remove("provisioningSubject");
        assertThatThrownBy(() -> provisioningDirectorySubjects(missing)).hasMessage("XINGYUAN_INPUT_INVALID");
        var interactive = registry.deepCopy(); ((com.fasterxml.jackson.databind.node.ObjectNode) interactive.path("subjects")).put("provisioner", "103");
        assertThatThrownBy(() -> provisioningDirectorySubjects(interactive)).hasMessage("XINGYUAN_TARGET_UNSAFE");
    }

    @Data @NoArgsConstructor @AllArgsConstructor @Accessors(chain = true) @Builder
    public static class ControlPlaneClientProofDTO {
        @Min(1) @Max(1) private int schemaVersion;
        @NotBlank private String runId;
        @NotBlank private String manifestSha256;
        @NotBlank @Pattern(regexp = "READY") private String status;
        @Min(6) @Max(6) private int membershipCount;
        @Min(4) @Max(4) private int catalogCount;
        @NotNull @com.fasterxml.jackson.annotation.JsonFormat(shape = com.fasterxml.jackson.annotation.JsonFormat.Shape.STRING) private Instant recordedAt;
    }





    private static UserPO platformUser(AnnotationConfigApplicationContext context, ResolvedPlatformBootstrapCommandDTO command) {
        var users = context.getBean("jpaSharedEM_entityManagerFactory", EntityManager.class).createQuery("""
                select user from UserEntity user where user.tenantId = :tenantId and user.identitySub = :subject
                """, UserPO.class).setParameter("tenantId", Long.valueOf(command.getTenantId()))
                .setParameter("subject", command.getIdentitySub()).getResultList();
        if (users.size() != 1) { throw new IllegalStateException("XINGYUAN_PARTIAL"); }
        return users.getFirst();
    }

    private static List<RolePO> platformRoles(AnnotationConfigApplicationContext context, ResolvedPlatformBootstrapCommandDTO command) {
        var definitions = Rbac3DevelopmentTopology.applications().subList(0, 4);
        var roles = context.getBean("jpaSharedEM_entityManagerFactory", EntityManager.class).createQuery("""
                select role from RoleEntity role where role.tenantId = :tenantId and role.roleCode in :codes
                """, RolePO.class).setParameter("tenantId", Long.valueOf(command.getTenantId()))
                .setParameter("codes", definitions.stream().map(definition -> definition.roleCode()).toList()).getResultList();
        if (roles.size() != 4) { throw new IllegalStateException("XINGYUAN_PARTIAL"); }
        return roles;
    }

    private static PlatformSnapshotProofVO confirmedPlatformSnapshot(AnnotationConfigApplicationContext context,
                                                                     ResolvedPlatformBootstrapCommandDTO command) {
        UserPO user = platformUser(context, command);
        var snapshot = context.getBean("postgresqlAuthorizationRuntimeRepository", PostgresqlAuthorizationRuntimeRepository.class)
                .load(command.getTenantId(), command.getIdentitySub());
        long policyVersion = context.getBean("jpaTenantAuthorizationStateRepository", TenantAuthorizationStateRepository.class)
                .require(Long.valueOf(command.getTenantId())).getPolicyVersion();
        if (snapshot == null || !command.getTenantId().equals(snapshot.tenantId())
                || !command.getIdentitySub().equals(snapshot.identitySub()) || !user.getId().toString().equals(snapshot.userId())
                || snapshot.snapshot().authVersion() != user.getAuthVersion() || snapshot.snapshot().policyVersion() != policyVersion
                || !snapshot.snapshot().expiresAt().isAfter(Instant.now())) { throw new IllegalStateException("XINGYUAN_PARTIAL"); }
        Set<String> selected = new HashSet<>();
        for (var definition : Rbac3DevelopmentTopology.applications().subList(0, 4)) {
            var app = snapshot.snapshot().appContexts().stream().filter(value -> definition.applicationCode().equals(value.applicationCode())).toList();
            if (app.size() != 1 || app.getFirst().activationRootRoleIds().size() != 1
                    || !app.getFirst().permissions().containsAll(definition.permissions())) { throw new IllegalStateException("XINGYUAN_PARTIAL"); }
            selected.addAll(app.getFirst().activationRootRoleIds());
        }
        if (!selected.equals(platformRoles(context, command).stream().map(role -> role.getId().toString()).collect(java.util.stream.Collectors.toSet()))) {
            throw new IllegalStateException("XINGYUAN_PARTIAL");
        }
        return context.getBean("platformSnapshotProofConverterImpl", PlatformSnapshotProofConverter.class)
                .toTarget(snapshot.snapshot());
    }

    static void validatePlatformCheckpoint(PlatformAuthorizationReceiptDTO receipt, VerifiedDatabaseInputsBO inputs, String commandHash, boolean resume) {
        try (var validators = Validation.buildDefaultValidatorFactory()) { new ValidationUtils(validators.getValidator()).validate(receipt); }
        if (!resume || !inputs.getManifest().getRunId().equals(receipt.getRunId())
                || !inputs.getManifestSha256().equals(receipt.getManifestSha256()) || inputs.getReceipt().getOid() != receipt.getDatabaseOid()
                || !commandHash.equals(receipt.getCommandSha256()) || "COMMITTED".equals(receipt.getStatus()) && receipt.getSnapshots().size() != 2) {
            throw new IllegalStateException("XINGYUAN_STATE_CONFLICT");
        }
    }

    @Test
    void aPlatformCheckpointCannotAuthorizeAnotherRunDatabaseOrCommandSet() throws Exception {
        var inputs = platformInputs();
        var pending = PlatformAuthorizationReceiptDTO.builder().schemaVersion(1).runId(inputs.getManifest().getRunId())
                .manifestSha256(inputs.getManifestSha256()).databaseOid(inputs.getReceipt().getOid()).commandSha256("b".repeat(64))
                .phase("platform").status("RUNNING").recordedAt(Instant.now()).snapshots(Map.of()).build();
        org.junit.jupiter.api.Assertions.assertDoesNotThrow(() -> validatePlatformCheckpoint(pending, inputs, "b".repeat(64), true));
        assertThatThrownBy(() -> validatePlatformCheckpoint(pending, inputs, "b".repeat(64), false)).isInstanceOf(IllegalStateException.class);
        pending.setDatabaseOid(999L);
        assertThatThrownBy(() -> validatePlatformCheckpoint(pending, inputs, "b".repeat(64), true)).isInstanceOf(IllegalStateException.class);
        pending.setDatabaseOid(inputs.getReceipt().getOid()).setRunId(UUID.randomUUID().toString());
        assertThatThrownBy(() -> validatePlatformCheckpoint(pending, inputs, "b".repeat(64), true)).isInstanceOf(IllegalStateException.class);
        pending.setRunId(inputs.getManifest().getRunId()).setStatus("COMMITTED");
        assertThatThrownBy(() -> validatePlatformCheckpoint(pending, inputs, "b".repeat(64), true)).isInstanceOf(IllegalStateException.class);
    }

    @Test
    void aPlatformReceiptPublicationRequiresTheExactPreviousBytes() throws Exception {
        var manifest = intent();
        preparedIntent(manifest);
        Path file = Path.of(manifest.getRuntimeRoot()).resolve("evidence/authorization-platform-owner.json");
        byte[] original = "first".getBytes(StandardCharsets.UTF_8);
        publishAuthorizationCheckpoint(file, original, null);
        assertThat(Files.getPosixFilePermissions(file)).isEqualTo(PosixFilePermissions.fromString("rw-------"));
        assertThatThrownBy(() -> publishAuthorizationCheckpoint(file, new byte[]{1}, new byte[]{2})).isInstanceOf(IllegalStateException.class);
        assertThat(Files.readAllBytes(file)).isEqualTo(original);
        byte[] confirmed = "second".getBytes(StandardCharsets.UTF_8);
        publishAuthorizationCheckpoint(file, confirmed, original);
        assertThat(Files.readAllBytes(file)).isEqualTo(confirmed);
    }

    private static String operationProperty(String name) {
        String value = System.getProperty(name);
        if (value == null || value.isBlank()) { throw new IllegalArgumentException("XINGYUAN_INPUT_INVALID"); }
        return value;
    }

    private static void publishAuthorizationCheckpoint(Path path, byte[] contents, byte[] expected) throws IOException {
        requirePrivateDirectory(path.getParent());
        if (expected == null ? Files.exists(path, LinkOption.NOFOLLOW_LINKS)
                : !MessageDigest.isEqual(expected, readProtectedBytes(path, path.getParent(), 128 * 1024))) {
            throw new IllegalStateException("XINGYUAN_STATE_CONFLICT");
        }
        Path temporary = Files.createTempFile(path.getParent(), ".authorization-", ".json",
                PosixFilePermissions.asFileAttribute(PosixFilePermissions.fromString("rw-------")));
        try {
            try (var output = FileChannel.open(temporary, StandardOpenOption.WRITE, StandardOpenOption.TRUNCATE_EXISTING)) {
                ByteBuffer buffer = ByteBuffer.wrap(contents);
                while (buffer.hasRemaining()) { output.write(buffer); }
                output.force(true);
            }
            Files.move(temporary, path, StandardCopyOption.ATOMIC_MOVE, StandardCopyOption.REPLACE_EXISTING);
            try (var directory = FileChannel.open(path.getParent(), StandardOpenOption.READ)) { directory.force(true); }
        } finally { Files.deleteIfExists(temporary); }
    }

    @Data @NoArgsConstructor @AllArgsConstructor @Accessors(chain = true) @Builder
    @JsonInclude(JsonInclude.Include.ALWAYS)
    public static class PlatformAuthorizationReceiptDTO {
        @Min(1) @Max(1) private int schemaVersion;
        @NotBlank private String runId;
        @NotBlank @Pattern(regexp = "[0-9a-f]{64}") private String manifestSha256;
        @Min(1) private long databaseOid;
        @NotBlank @Pattern(regexp = "[0-9a-f]{64}") private String commandSha256;
        @NotBlank @Pattern(regexp = "platform") private String phase;
        @NotBlank @Pattern(regexp = "RUNNING|COMMITTED") private String status;
        @NotNull @com.fasterxml.jackson.annotation.JsonFormat(shape = com.fasterxml.jackson.annotation.JsonFormat.Shape.STRING) private Instant recordedAt;
        @NotNull @Size(max = 2) @Valid private Map<@NotBlank String, PlatformSnapshotProofVO> snapshots;
    }

    @Data @NoArgsConstructor @AllArgsConstructor @Accessors(chain = true) @Builder
    public static class PlatformSnapshotProofVO {
        @NotBlank private String tenantId;
        @NotBlank @lombok.ToString.Exclude private String rbacUserId;
        @Min(0) private long authVersion;
        @Min(0) private long policyVersion;
        @NotNull @Size(min = 4, max = 4) private List<@NotBlank String> selectedRoleIds;
        @NotBlank private String snapshotChecksum;
        @NotNull @com.fasterxml.jackson.annotation.JsonFormat(shape = com.fasterxml.jackson.annotation.JsonFormat.Shape.STRING) private Instant expiresAt;
    }

    @org.mapstruct.Mapper(componentModel = "spring", implementationName = "PlatformSnapshotProofConverterImpl",
            unmappedTargetPolicy = org.mapstruct.ReportingPolicy.ERROR)
    public interface PlatformSnapshotProofConverter extends top.egon.cola.component.common.core.converter.BaseForwardConverter<
            top.egon.cola.platform.tianquan.jianshen.contract.authorization.UserAuthorizationSnapshot, PlatformSnapshotProofVO> {
        @Override
        @org.mapstruct.Mapping(target = "snapshotChecksum", source = "checksum", qualifiedByName = "canonicalSnapshotChecksum")
        @org.mapstruct.Mapping(target = "selectedRoleIds", source = "appContexts", qualifiedByName = "platformRootIds")
        PlatformSnapshotProofVO toTarget(top.egon.cola.platform.tianquan.jianshen.contract.authorization.UserAuthorizationSnapshot source);

        @org.mapstruct.Named("canonicalSnapshotChecksum")
        default String canonicalSnapshotChecksum(String checksum) {
            if (checksum == null || !checksum.matches("(?:sha256:)?[0-9a-f]{64}")) {
                throw new IllegalArgumentException("XINGYUAN_INPUT_INVALID");
            }
            return checksum.startsWith("sha256:") ? checksum.substring("sha256:".length()) : checksum;
        }

        @org.mapstruct.Named("platformRootIds")
        default List<String> platformRootIds(List<top.egon.cola.platform.tianquan.jianshen.contract.authorization.AppAuthorizationContext> applications) {
            Set<String> codes = Rbac3DevelopmentTopology.applications().subList(0, 4).stream()
                    .map(definition -> definition.applicationCode()).collect(java.util.stream.Collectors.toSet());
            return applications.stream().filter(app -> codes.contains(app.applicationCode()))
                    .flatMap(app -> app.activationRootRoleIds().stream()).distinct().sorted().toList();
        }
    }

    @Test
    void aPlatformSnapshotProofExcludesOtherApplicationsAndTheIdentitySubject() {
        var applications = new java.util.ArrayList<top.egon.cola.platform.tianquan.jianshen.contract.authorization.AppAuthorizationContext>();
        for (int i = 0; i < 4; i++) {
            applications.add(new top.egon.cola.platform.tianquan.jianshen.contract.authorization.AppAuthorizationContext(
                    Long.toString(100L + i), Rbac3DevelopmentTopology.applications().get(i).applicationCode(), List.of("role-" + i),
                    List.of(), List.of("role-" + i), Set.of(), Map.of(), Map.of(), List.of(), null));
        }
        applications.add(new top.egon.cola.platform.tianquan.jianshen.contract.authorization.AppAuthorizationContext(
                "999", "native-owner", List.of("native-role"), List.of(), List.of("native-role"), Set.of(), Map.of(), Map.of(), List.of(), null));
        var snapshot = new top.egon.cola.platform.tianquan.jianshen.contract.authorization.UserAuthorizationSnapshot(
                "controlled", "1001", "controlled-private-subject", "2001", 3L, 4L, applications, "c".repeat(64), Instant.now(), Instant.now().plusSeconds(300));
        PlatformSnapshotProofVO proof = new PlatformSnapshotProofConverterImpl().toTarget(snapshot);
        assertThat(proof.getSelectedRoleIds()).containsExactly("role-0", "role-1", "role-2", "role-3");
        assertThat(proof.getRbacUserId()).isEqualTo("2001");
        assertThat(proof.getAuthVersion()).isEqualTo(3L);
        assertThat(proof.getPolicyVersion()).isEqualTo(4L);
        assertThat(proof.getSnapshotChecksum()).isEqualTo("c".repeat(64));
        assertThat(proof.toString()).doesNotContain("controlled-private-subject", "2001");
    }

    @Test
    void aPlatformSnapshotProofPreservesTheOriginalBuilderDigest() throws IOException {
        Instant now = Instant.parse("2026-10-15T00:00:00Z");
        var roles = new java.util.ArrayList<top.egon.cola.platform.tianquan.jianshen.core.hierarchy.RoleNode>();
        var applications = new LinkedHashMap<String, top.egon.cola.platform.tianquan.jianshen.admin.authorization.runtime.activation.domain.vo.ApplicationFactVO>();
        Map<String, Set<String>> roots = new LinkedHashMap<>();
        for (int i = 0; i < 4; i++) {
            String applicationId = Long.toString(100L + i);
            String roleId = Long.toString(200L + i);
            String applicationCode = Rbac3DevelopmentTopology.applications().get(i).applicationCode();
            roles.add(new top.egon.cola.platform.tianquan.jianshen.core.hierarchy.RoleNode(
                    roleId, applicationId, "PLATFORM_" + i, true,
                    top.egon.cola.platform.tianquan.jianshen.core.hierarchy.RoleNode.RiskLevel.LOW, false, null, 1));
            applications.put(applicationId,
                    new top.egon.cola.platform.tianquan.jianshen.admin.authorization.runtime.activation.domain.vo.ApplicationFactVO(
                            applicationId, applicationCode, applicationCode));
            roots.put(applicationId, Set.of(roleId));
        }
        var hierarchy = new top.egon.cola.platform.tianquan.jianshen.core.hierarchy.RoleHierarchy(roles, List.of());
        var rules = new top.egon.cola.platform.tianquan.jianshen.core.activation.AuthorizationRuleFacts(
                List.of(), List.of(), List.of(), List.of(), List.of());
        var canonical = new top.egon.cola.platform.tianquan.jianshen.core.decision.UserAuthorizationSnapshotBuilder().build(
                roots.values().stream().flatMap(Set::stream).collect(java.util.stream.Collectors.toSet()),
                hierarchy, rules, 3L, 3L, 4L);
        var facts = new top.egon.cola.platform.tianquan.jianshen.admin.authorization.runtime.activation.domain.vo.ActivationFactsVO(
                "1001", "2001", hierarchy, List.of(), List.of(), rules, 3L, 4L, "directory:1", applications, Map.of());
        var resolution = new top.egon.cola.platform.tianquan.jianshen.core.activation.RoleActivationResolution(
                new top.egon.cola.platform.tianquan.jianshen.core.activation.ActiveRoleSet("1001", "2001", roots, "active"),
                canonical, List.of());
        var snapshot = new top.egon.cola.platform.tianquan.jianshen.admin.authorization.runtime.service.UserAuthorizationSnapshotProjector()
                .project(new top.egon.cola.platform.tianquan.jianshen.admin.authorization.runtime.domain.dto.ProjectionCommandDTO(
                        "1001", "controlled-private-subject", "2001", 3L, 4L, now.plusSeconds(300), resolution, facts, now))
                .snapshot();

        PlatformSnapshotProofVO proof = new PlatformSnapshotProofConverterImpl().toTarget(snapshot);

        assertThat(canonical.checksum()).matches("sha256:[0-9a-f]{64}");
        assertThat(snapshot.checksum()).isEqualTo(canonical.checksum());
        assertThat(proof.getSnapshotChecksum()).isEqualTo(canonical.checksum().substring("sha256:".length()));
        assertThat(proof.getSelectedRoleIds()).containsExactly("200", "201", "202", "203");
        assertThat(strictMapper().writeValueAsString(proof)).doesNotContain("identitySub", "controlled-private-subject");
        assertThat(proof.toString()).doesNotContain("controlled-private-subject", "2001");
    }

    @Test
    void aPlatformSnapshotProofRejectsMalformedChecksums() {
        var converter = new PlatformSnapshotProofConverterImpl();
        Instant now = Instant.parse("2026-10-15T00:00:00Z");
        for (String checksum : List.of("c".repeat(63), "c".repeat(65), "C".repeat(64),
                "SHA256:" + "c".repeat(64), "sha512:" + "c".repeat(64), "sha256:" + "c".repeat(63),
                "sha256:" + "C".repeat(64))) {
            var snapshot = new top.egon.cola.platform.tianquan.jianshen.contract.authorization.UserAuthorizationSnapshot(
                    "controlled", "1001", "controlled-private-subject", "2001", 3L, 4L, List.of(), checksum,
                    now, now.plusSeconds(300));
            assertThatThrownBy(() -> converter.toTarget(snapshot))
                    .isInstanceOf(IllegalArgumentException.class).hasMessage("XINGYUAN_INPUT_INVALID");
        }
    }

    @Test
    void aPlatformSnapshotChecksumConversionRejectsNullAndUntrimmedInputs() {
        var converter = new PlatformSnapshotProofConverterImpl();
        for (String checksum : Arrays.asList(null, "", "sha256:" + "c".repeat(64) + " ", " " + "c".repeat(64))) {
            assertThatThrownBy(() -> converter.canonicalSnapshotChecksum(checksum))
                    .isInstanceOf(IllegalArgumentException.class).hasMessage("XINGYUAN_INPUT_INVALID");
        }
    }

    static List<ResolvedPlatformBootstrapCommandDTO> platformBootstrapCommands(VerifiedDatabaseInputsBO inputs) throws IOException {
        Path root = Path.of(inputs.getManifest().getRuntimeRoot());
        requirePrivateDirectory(root.resolve("secrets"));
        requirePrivateDirectory(root.resolve("policies"));
        byte[] registryBytes = readProtectedBytes(root.resolve("secrets/runtime-registry.json"), root.resolve("secrets"), 2 * 1024 * 1024);
        var registry = strictMapper().readTree(registryBytes);
        var catalog = strictMapper().readTree(readProtectedBytes(root.resolve("evidence/tianshu-platform-catalog.json"), root.resolve("evidence"), 128 * 1024));
        requireExactFields(catalog, Set.of("schemaVersion", "runId", "manifestSha256", "databaseOid", "recipeSha256", "registrySha256",
                "tenantId", "status", "recordedAt", "businesses", "applications"));
        var control = strictMapper().readTree(readProtectedBytes(root.resolve("evidence/control-plane.json"), root.resolve("evidence"), 128 * 1024));
        requireExactFields(control, Set.of("schemaVersion", "operationId", "runId", "manifestSha256", "status", "completedAt", "targets", "counts", "steps", "error"));
        for (var document : List.of(registry, catalog, control)) {
            if (!document.path("schemaVersion").isIntegralNumber() || document.path("schemaVersion").intValue() != 1
                    || !inputs.getManifest().getRunId().equals(requiredJsonText(document, "runId", 36))
                    || !inputs.getManifestSha256().equals(requiredJsonText(document, "manifestSha256", 64))) {
                throw new IllegalArgumentException("XINGYUAN_TARGET_UNSAFE");
            }
        }
        if (!"CLI-003".equals(requiredJsonText(control, "operationId", 32)) || !"RUNNING".equals(requiredJsonText(control, "status", 32))
                || !control.path("error").isNull() || !control.path("targets").isArray() || control.path("targets").isEmpty()
                || control.path("targets").size() > 32 || !control.path("steps").isArray() || control.path("steps").size() > 32
                || !"COMMITTED".equals(requiredJsonText(catalog, "status", 32))
                || !digest(registryBytes).equals(requiredJsonText(catalog, "registrySha256", 64))) {
            throw new IllegalArgumentException("XINGYUAN_STATE_CONFLICT");
        }
        requireUtcInstant(requiredJsonText(control, "completedAt", 64));
        requireUtcInstant(requiredJsonText(catalog, "recordedAt", 64));
        requireExactFields(control.path("counts"), Set.of("databaseCount", "tenantCount", "clientCount", "catalogCount", "liveCaseCount"));
        for (var count : control.path("counts")) {
            if (!count.isIntegralNumber() || !count.canConvertToLong() || count.longValue() < 0L) {
                throw new IllegalArgumentException("XINGYUAN_INPUT_INVALID");
            }
        }
        if (control.path("counts").path("databaseCount").longValue() != 9L
                || control.path("counts").path("tenantCount").longValue() != 2L
                || control.path("counts").path("liveCaseCount").longValue() != 0L) {
            throw new IllegalArgumentException("XINGYUAN_STATE_CONFLICT");
        }
        for (var target : control.path("targets")) {
            requireExactFields(target, Set.of("targetKey", "identity", "version", "state"));
            requiredJsonText(target, "targetKey", 128);
            String pid = requiredJsonText(target, "identity", 10);
            if (!pid.matches("[1-9][0-9]{0,9}") || Long.parseLong(pid) > Integer.MAX_VALUE
                    || !"RUNNING".equals(requiredJsonText(target, "state", 32))) {
                throw new IllegalArgumentException("XINGYUAN_INPUT_INVALID");
            }
            requireUtcInstant(requiredJsonText(target, "version", 64));
        }
        var tianshuReceipt = strictMapper().readValue(readProtectedBytes(root.resolve("evidence/db-tianshu.json"), root.resolve("evidence"), 128 * 1024), IsolatedDatabaseReceiptDTO.class);
        validateDatabaseReceipt(inputs.getManifest(), inputs.getManifestSha256(), "tianshu", tianshuReceipt);
        if (!catalog.path("databaseOid").isIntegralNumber() || !catalog.path("databaseOid").canConvertToLong()
                || catalog.path("databaseOid").longValue() != tianshuReceipt.getOid()) {
            throw new IllegalArgumentException("XINGYUAN_TARGET_UNSAFE");
        }
        Path recipeFile = root.resolve("policies/platform-catalog.json");
        var references = inputs.getManifest().getPolicyFiles().stream().filter(ref -> recipeFile.toString().equals(ref.getPath())).toList();
        byte[] recipeBytes = readProtectedBytes(recipeFile, root, 128 * 1024);
        if (references.size() != 1 || !digest(recipeBytes).equals(references.getFirst().getSha256())
                || !digest(recipeBytes).equals(requiredJsonText(catalog, "recipeSha256", 64))) {
            throw new IllegalArgumentException("XINGYUAN_TARGET_UNSAFE");
        }
        var recipe = strictMapper().readTree(recipeBytes);
        requireExactFields(recipe, Set.of("schemaVersion", "runId", "tenantKey", "actorKey", "businesses", "applications"));
        if (!recipe.path("schemaVersion").isIntegralNumber() || recipe.path("schemaVersion").intValue() != 1
                || !inputs.getManifest().getRunId().equals(requiredJsonText(recipe, "runId", 36))
                || !"default".equals(requiredJsonText(recipe, "tenantKey", 64)) || !"admin".equals(requiredJsonText(recipe, "actorKey", 64))) {
            throw new IllegalArgumentException("XINGYUAN_TARGET_UNSAFE");
        }
        String actor = requiredJsonText(registry.path("subjects"), "admin", 128);
        if (!actor.equals(actor.strip()) || actor.chars().anyMatch(Character::isISOControl)) {
            throw new IllegalArgumentException("XINGYUAN_INPUT_INVALID");
        }
        var tenants = registry.path("tenantIds");
        requireExactFields(tenants, Set.of("default", "tenant-b"));
        String firstTenant = requiredPublicId(tenants, "default");
        String secondTenant = requiredPublicId(tenants, "tenant-b");
        if (firstTenant.equals(secondTenant) || firstTenant.equals(inputs.getManifest().getPlatformStoragePartitionId())
                || secondTenant.equals(inputs.getManifest().getPlatformStoragePartitionId())
                || !firstTenant.equals(requiredJsonText(catalog, "tenantId", 19))) {
            throw new IllegalArgumentException("XINGYUAN_TARGET_UNSAFE");
        }
        List<PlatformCatalogBindingDTO> bindings = platformCatalogBindings(catalog, recipe, actor, inputs.getManifest().getRunId());
        return List.of(firstTenant, secondTenant).stream().map(tenant -> ResolvedPlatformBootstrapCommandDTO.builder()
                .tenantId(tenant).identitySub(actor).applications(bindings.stream().map(binding -> PlatformCatalogBindingDTO.builder()
                        .applicationCode(binding.getApplicationCode()).businessCode(binding.getBusinessCode())
                        .ddcApplicationId(binding.getDdcApplicationId()).ddcBusinessId(binding.getDdcBusinessId()).build()).toList()).build()).toList();
    }

    private static List<PlatformCatalogBindingDTO> platformCatalogBindings(com.fasterxml.jackson.databind.JsonNode catalog,
            com.fasterxml.jackson.databind.JsonNode recipe, String actor, String runId) {
        List<String> codes = List.of("tianquan-jianshen-admin", "tianquan-shoubing-admin", "stellar-enclosure-yuheng-admin", "tianshu-admin");
        List<String> businessCodes = List.of("permission", "identity", "platform", "platform");
        requireExactFields(catalog.path("businesses"), Set.of("permission", "identity", "platform"));
        requireExactFields(catalog.path("applications"), Set.copyOf(codes));
        if (!recipe.path("businesses").isArray() || recipe.path("businesses").size() != 3
                || !recipe.path("applications").isArray() || recipe.path("applications").size() != 4) {
            throw new IllegalArgumentException("XINGYUAN_INPUT_INVALID");
        }
        Map<String, String> businessNames = new LinkedHashMap<>();
        Map<String, String> applicationNames = new LinkedHashMap<>();
        for (var value : recipe.path("businesses")) {
            requireExactFields(value, Set.of("bizCode", "bizName"));
            if (businessNames.put(requiredJsonText(value, "bizCode", 128), requiredJsonText(value, "bizName", 128)) != null) {
                throw new IllegalArgumentException("XINGYUAN_INPUT_INVALID");
            }
        }
        for (var value : recipe.path("applications")) {
            requireExactFields(value, Set.of("appCode", "appName", "bizCode"));
            String code = requiredJsonText(value, "appCode", 128);
            int index = codes.indexOf(code);
            if (index < 0 || !businessCodes.get(index).equals(requiredJsonText(value, "bizCode", 128))
                    || applicationNames.put(code, requiredJsonText(value, "appName", 128)) != null) {
                throw new IllegalArgumentException("XINGYUAN_INPUT_INVALID");
            }
        }
        var businessIds = new LinkedHashMap<String, String>();
        Set<String> publicIds = new HashSet<>();
        String marker = "xingyuan-it:" + runId + ":platform-catalog";
        for (String code : List.of("permission", "identity", "platform")) {
            var fact = catalog.path("businesses").path(code);
            requireExactFields(fact, Set.of("id", "bizCode", "bizName", "description", "enabled", "createdAt", "updatedAt"));
            String id = requiredPublicId(fact, "id");
            if (!publicIds.add(id) || !code.equals(requiredJsonText(fact, "bizCode", 128))
                    || !Objects.equals(businessNames.get(code), requiredJsonText(fact, "bizName", 128))
                    || !marker.equals(requiredJsonText(fact, "description", 512)) || !fact.path("enabled").isBoolean() || !fact.path("enabled").booleanValue()) {
                throw new IllegalArgumentException("XINGYUAN_TARGET_UNSAFE");
            }
            businessIds.put(code, id);
        }
        List<PlatformCatalogBindingDTO> bindings = new java.util.ArrayList<>();
        for (int i = 0; i < codes.size(); i++) {
            String code = codes.get(i);
            var fact = catalog.path("applications").path(code);
            requireExactFields(fact, Set.of("id", "appCode", "bizCode", "appName", "owner", "description", "enabled", "createdAt", "updatedAt"));
            String id = requiredPublicId(fact, "id");
            if (!publicIds.add(id) || !code.equals(requiredJsonText(fact, "appCode", 128))
                    || !businessCodes.get(i).equals(requiredJsonText(fact, "bizCode", 128))
                    || !Objects.equals(applicationNames.get(code), requiredJsonText(fact, "appName", 128))
                    || !actor.equals(requiredJsonText(fact, "owner", 128)) || !marker.equals(requiredJsonText(fact, "description", 512))
                    || !fact.path("enabled").isBoolean() || !fact.path("enabled").booleanValue()) {
                throw new IllegalArgumentException("XINGYUAN_TARGET_UNSAFE");
            }
            bindings.add(PlatformCatalogBindingDTO.builder().applicationCode(code).businessCode(businessCodes.get(i))
                    .ddcApplicationId(id).ddcBusinessId(businessIds.get(businessCodes.get(i))).build());
        }
        return List.copyOf(bindings);
    }

    /** Select a previously acquired formal PUBLIC input; the real metadata server still verifies the bearer. */
    static NativeMetadataCallerBO readNativeMetadataCaller(VerifiedDatabaseInputsBO inputs, Path tokenIndex) throws IOException {
        Path root = Path.of(inputs.getManifest().getRuntimeRoot());
        if (!root.resolve("secrets/token-index.json").equals(tokenIndex)) { throw new IllegalArgumentException("XINGYUAN_TARGET_UNSAFE"); }
        var registry = strictMapper().readTree(readProtectedBytes(root.resolve("secrets/runtime-registry.json"), root, 2 * 1024 * 1024));
        var index = strictMapper().readTree(readProtectedBytes(tokenIndex, root, 128 * 1024));
        requireExactFields(index, Set.of("schemaVersion", "runId", "manifestSha256", "tokens"));
        for (var document : List.of(registry, index)) {
            if (!document.path("schemaVersion").isIntegralNumber() || document.path("schemaVersion").intValue() != 1
                    || !inputs.getManifest().getRunId().equals(requiredJsonText(document, "runId", 36))
                    || !inputs.getManifestSha256().equals(requiredJsonText(document, "manifestSha256", 64))) {
                throw new IllegalArgumentException("XINGYUAN_TARGET_UNSAFE");
            }
        }
        String tenantId = requiredPublicId(registry.path("tenantIds"), "default");
        String issuer = inputs.getManifest().getPublicOrigin() + "/tenants/" + tenantId;
        var resources = registry.path("resources");
        var bindings = registry.path("cliResources");
        var clients = registry.path("clients");
        var tokens = index.path("tokens");
        if (!resources.isArray() || resources.size() > 64 || !bindings.isArray() || bindings.size() > 64
                || !clients.isArray() || clients.size() > 192 || !tokens.isArray() || tokens.size() > 192) {
            throw new IllegalArgumentException("XINGYUAN_INPUT_INVALID");
        }
        var selectedResources = java.util.stream.StreamSupport.stream(resources.spliterator(), false)
                .filter(item -> "tianshu-admin".equals(item.path("rbacApplicationCode").asText())).toList();
        if (selectedResources.size() != 1 || !"ACTIVE".equals(selectedResources.getFirst().path("status").asText())) {
            throw new IllegalArgumentException("XINGYUAN_TARGET_UNSAFE");
        }
        var resource = selectedResources.getFirst();
        String resourceId = requiredJsonText(resource, "resourceServerId", 128);
        String resourceUri = requiredJsonText(resource, "resourceUri", 2048);
        var selectedBindings = java.util.stream.StreamSupport.stream(bindings.spliterator(), false)
                .filter(item -> resourceId.equals(item.path("resourceServerId").asText())).toList();
        if (selectedBindings.size() != 1) { throw new IllegalArgumentException("XINGYUAN_TARGET_UNSAFE"); }
        String key = requiredJsonText(selectedBindings.getFirst(), "resourceKey", 64);
        String clientId = requiredJsonText(selectedBindings.getFirst().path("clientIds"), "default", 128);
        var selectedClients = java.util.stream.StreamSupport.stream(clients.spliterator(), false)
                .filter(item -> "default".equals(item.path("realmCode").asText()) && clientId.equals(item.path("clientId").asText())).toList();
        var selectedTokens = java.util.stream.StreamSupport.stream(tokens.spliterator(), false)
                .filter(item -> "default".equals(item.path("tenantCode").asText()) && "admin".equals(item.path("userKey").asText())
                        && key.equals(item.path("resourceKey").asText())).toList();
        if (selectedClients.size() != 1 || selectedTokens.size() != 1) { throw new IllegalArgumentException("XINGYUAN_INPUT_INVALID"); }
        var client = selectedClients.getFirst();
        var token = selectedTokens.getFirst();
        requireExactFields(token, Set.of("tenantCode", "tenantId", "resourceKey", "userKey", "clientId", "clientPk", "issuer",
                "resourceUri", "scopes", "tokenFile", "probeStatus", "tokenSha256", "expiresAt"));
        var probeStatus = token.path("probeStatus");
        if (!probeStatus.isNull() && (!probeStatus.isIntegralNumber() || !probeStatus.canConvertToInt()
                || !Set.of(200, 403).contains(probeStatus.intValue()))) {
            throw new IllegalArgumentException("XINGYUAN_INPUT_INVALID");
        }
        String clientPk = client.path("clientPk").asText();
        if (!clientPk.matches("[1-9][0-9]{0,18}") || new java.math.BigInteger(clientPk).compareTo(java.math.BigInteger.valueOf(Long.MAX_VALUE)) > 0
                || !"PUBLIC".equals(client.path("clientType").asText()) || !"USER".equals(client.path("purpose").asText())
                || !"ACTIVE".equals(client.path("status").asText()) || !issuer.equals(client.path("issuer").asText())
                || !client.path("resourceUris").equals(strictMapper().valueToTree(List.of(resourceUri)))
                || !client.path("refreshTokenTtlSeconds").canConvertToInt() || !client.path("refreshTokenTtlSeconds").isIntegralNumber()
                || client.path("refreshTokenTtlSeconds").intValue() != 0
                || !clientId.equals(token.path("clientId").asText()) || !clientPk.equals(token.path("clientPk").asText())
                || !tenantId.equals(token.path("tenantId").asText()) || !issuer.equals(token.path("issuer").asText())
                || !resourceUri.equals(token.path("resourceUri").asText())) { throw new IllegalArgumentException("XINGYUAN_TARGET_UNSAFE"); }
        Set<String> approvedScopes = validatedScopeSet(client.path("allowedScopes"));
        Set<String> actualScopes = validatedScopeSet(token.path("scopes"));
        if (!approvedScopes.equals(actualScopes) || !actualScopes.containsAll(Set.of("TIANSHU_READ", "TIANSHU_WRITE"))
                || actualScopes.contains("offline_access")) { throw new IllegalArgumentException("XINGYUAN_TARGET_UNSAFE"); }
        String expiry = requiredJsonText(token, "expiresAt", 64);
        requireUtcInstant(expiry);
        if (!Instant.parse(expiry).isAfter(Instant.now())) { throw new IllegalStateException("XINGYUAN_INPUT_EXPIRED"); }
        Path tokenFile = Path.of(requiredJsonText(token, "tokenFile", 4096));
        byte[] value = readProtectedBytes(tokenFile, root.resolve("secrets"), 128 * 1024);
        try {
            if (value.length == 0 || !digest(value).equals(requiredJsonText(token, "tokenSha256", 64))) {
                throw new IllegalArgumentException("XINGYUAN_TARGET_UNSAFE");
            }
        } finally { Arrays.fill(value, (byte) 0); }
        return NativeMetadataCallerBO.builder().tenantId(tenantId).identitySub(requiredJsonText(registry.path("subjects"), "admin", 128))
                .clientId(clientId).issuer(issuer).resourceUri(resourceUri).tokenFile(tokenFile.toString())
                .tokenSha256(requiredJsonText(token, "tokenSha256", 64)).expiresAt(Instant.parse(expiry)).build();
    }

    @Test
    void nativeMetadataInputRejectsWrongRealmServiceClientExpiredOrChangedTokenFile() throws Exception {
        var manifest = intent();
        Path root = Path.of(manifest.getRuntimeRoot());
        Files.createDirectories(root.resolve("secrets")); privateDirectory(root); privateDirectory(root.resolve("secrets"));
        var inputs = VerifiedDatabaseInputsBO.builder().manifest(manifest).manifestSha256("a".repeat(64)).build();
        Path tokenFile = root.resolve("secrets/formal-tianshu.at");
        Files.writeString(tokenFile, "controlled-file-only-token");
        Files.setPosixFilePermissions(tokenFile, PosixFilePermissions.fromString("rw-------"));
        String issuer = manifest.getPublicOrigin() + "/tenants/1001";
        String resourceUri = "https://127.0.0.1:28150";
        Map<String, Object> client = new LinkedHashMap<>();
        client.put("clientPk", 9007199254740993L); client.put("clientId", "formal-tianshu-a");
        client.put("realmCode", "default"); client.put("issuer", issuer); client.put("clientType", "PUBLIC");
        client.put("purpose", "USER"); client.put("status", "ACTIVE"); client.put("refreshTokenTtlSeconds", 0);
        client.put("resourceUris", List.of(resourceUri)); client.put("allowedScopes", List.of("openid", "TIANSHU_READ", "TIANSHU_WRITE"));
        Path registry = root.resolve("secrets/runtime-registry.json");
        Map<String, Object> registryBody = Map.of("schemaVersion", 1, "runId", manifest.getRunId(), "manifestSha256", inputs.getManifestSha256(),
                "tenantIds", Map.of("default", "1001", "tenant-b", "1002"), "subjects", Map.of("admin", "controlled-subject"),
                "resources", List.of(Map.of("resourceServerId", "resource-tianshu", "resourceUri", resourceUri,
                        "rbacApplicationCode", "tianshu-admin", "status", "ACTIVE")),
                "cliResources", List.of(Map.of("resourceServerId", "resource-tianshu", "resourceKey", "tianshu",
                        "clientIds", Map.of("default", "formal-tianshu-a", "tenant-b", "formal-tianshu-b"))), "clients", List.of(client));
        privateJson(registry, registryBody);
        Map<String, Object> token = new LinkedHashMap<>();
        token.put("tenantCode", "default"); token.put("tenantId", "1001"); token.put("resourceKey", "tianshu"); token.put("userKey", "admin");
        token.put("clientId", "formal-tianshu-a"); token.put("clientPk", "9007199254740993"); token.put("issuer", issuer);
        token.put("resourceUri", resourceUri); token.put("scopes", client.get("allowedScopes")); token.put("tokenFile", tokenFile.toString());
        token.put("probeStatus", 200); token.put("tokenSha256", digest(Files.readAllBytes(tokenFile)));
        token.put("expiresAt", Instant.now().plusSeconds(120).toString());
        Path index = root.resolve("secrets/token-index.json");
        Map<String, Object> indexBody = Map.of("schemaVersion", 1, "runId", manifest.getRunId(),
                "manifestSha256", inputs.getManifestSha256(), "tokens", List.of(token));
        privateJson(index, indexBody);
        assertThat(readNativeMetadataCaller(inputs, index).getClientId()).isEqualTo("formal-tianshu-a");
        token.put("probeStatus", null);
        Files.write(index, strictMapper().writeValueAsBytes(indexBody), StandardOpenOption.TRUNCATE_EXISTING);
        org.assertj.core.api.Assertions.assertThatCode(() -> readNativeMetadataCaller(inputs, index)).doesNotThrowAnyException();
        token.put("probeStatus", 200);
        token.put("tenantId", "1002");
        Files.write(index, strictMapper().writeValueAsBytes(indexBody), StandardOpenOption.TRUNCATE_EXISTING);
        assertThatThrownBy(() -> readNativeMetadataCaller(inputs, index)).isInstanceOf(IllegalArgumentException.class);
        token.put("tenantId", "1001"); token.put("expiresAt", Instant.now().minusSeconds(1).toString());
        Files.write(index, strictMapper().writeValueAsBytes(indexBody), StandardOpenOption.TRUNCATE_EXISTING);
        assertThatThrownBy(() -> readNativeMetadataCaller(inputs, index)).isInstanceOf(IllegalStateException.class);
        token.put("expiresAt", Instant.now().plusSeconds(120).toString());
        Files.write(index, strictMapper().writeValueAsBytes(indexBody), StandardOpenOption.TRUNCATE_EXISTING);
        client.put("clientType", "CONFIDENTIAL"); client.put("purpose", "SERVICE");
        Files.write(registry, strictMapper().writeValueAsBytes(registryBody), StandardOpenOption.TRUNCATE_EXISTING);
        assertThatThrownBy(() -> readNativeMetadataCaller(inputs, index)).isInstanceOf(IllegalArgumentException.class);
        client.put("clientType", "PUBLIC"); client.put("purpose", "USER");
        Files.write(registry, strictMapper().writeValueAsBytes(registryBody), StandardOpenOption.TRUNCATE_EXISTING);
        Files.writeString(tokenFile, "changed-file", StandardOpenOption.TRUNCATE_EXISTING);
        assertThatThrownBy(() -> readNativeMetadataCaller(inputs, index)).isInstanceOf(IllegalArgumentException.class);
    }

    private static Set<String> validatedScopeSet(com.fasterxml.jackson.databind.JsonNode scopes) {
        if (!scopes.isArray() || scopes.isEmpty() || scopes.size() > 64) { throw new IllegalArgumentException("XINGYUAN_INPUT_INVALID"); }
        Set<String> result = new HashSet<>();
        for (var scope : scopes) {
            if (!scope.isTextual() || !scope.textValue().matches("[A-Za-z0-9._:-]{1,128}") || !result.add(scope.textValue())) {
                throw new IllegalArgumentException("XINGYUAN_INPUT_INVALID");
            }
        }
        return Set.copyOf(result);
    }

    @Data @NoArgsConstructor @AllArgsConstructor @Accessors(chain = true) @Builder
    public static class NativeMetadataCallerBO {
        @NotBlank private String tenantId;
        @lombok.ToString.Exclude @NotBlank private String identitySub;
        @NotBlank private String clientId;
        @NotBlank private String issuer;
        @NotBlank private String resourceUri;
        @NotBlank private String tokenFile;
        @NotBlank private String tokenSha256;
        @NotNull private Instant expiresAt;
    }

    @Data @NoArgsConstructor @AllArgsConstructor @Accessors(chain = true) @Builder
    @JsonInclude(JsonInclude.Include.NON_NULL)
    public static class NativeMetadataCreateCommandDTO {
        @NotBlank @Pattern(regexp = "[A-Za-z0-9][A-Za-z0-9_.-]{0,127}") private String bizCode;
        @Pattern(regexp = "[A-Za-z0-9][A-Za-z0-9_.-]{0,127}") private String appCode;
        @Size(min = 1, max = 128) private String bizName;
        @Size(min = 1, max = 128) private String appName;
        @Size(min = 1, max = 128) private String owner;
        @NotBlank @Size(max = 512) private String description;
        @NotNull @jakarta.validation.constraints.AssertTrue private Boolean enabled;

        @com.fasterxml.jackson.annotation.JsonIgnore
        @jakarta.validation.constraints.AssertTrue
        public boolean isShapeValid() {
            return appCode == null ? bizName != null && appName == null && owner == null
                    : bizName == null && appName != null && owner != null;
        }
    }

    @Data @NoArgsConstructor @AllArgsConstructor @Accessors(chain = true) @Builder
    public static class NativeMetadataReceiptDTO {
        @Min(1) @Max(1) private int schemaVersion;
        @NotBlank private String runId;
        @NotBlank private String manifestSha256;
        @NotBlank @Pattern(regexp = "RUNNING|COMMITTED") private String status;
        @NotNull @com.fasterxml.jackson.annotation.JsonFormat(shape = com.fasterxml.jackson.annotation.JsonFormat.Shape.STRING) private Instant recordedAt;
        @NotNull @Size(max = 4) private Map<@NotBlank String, @NotBlank String> businesses;
        @NotNull @Size(max = 4) private Map<@NotBlank String, @NotBlank String> applications;
    }

    static String validateNativeMetadataRecord(com.fasterxml.jackson.databind.JsonNode value,
            @jakarta.validation.Valid NativeMetadataCreateCommandDTO expected, String expectedId) {
        try (var validators = Validation.buildDefaultValidatorFactory()) {
            if (expected == null || !validators.getValidator().validate(expected).isEmpty()) {
                throw new IllegalArgumentException("XINGYUAN_INPUT_INVALID");
            }
        }
        boolean app = expected.getAppCode() != null;
        Set<String> fields = app ? Set.of("id", "appCode", "bizCode", "appName", "owner", "description", "enabled", "createdAt", "updatedAt")
                : Set.of("id", "bizCode", "bizName", "description", "enabled", "createdAt", "updatedAt");
        Set<String> actualFields = new HashSet<>(); value.fieldNames().forEachRemaining(actualFields::add);
        if (!value.isObject() || !fields.containsAll(actualFields)
                || !value.path("bizCode").isTextual() || !value.path("description").isTextual()
                || app && (!value.path("appCode").isTextual() || !value.path("appName").isTextual() || !value.path("owner").isTextual())
                || !app && !value.path("bizName").isTextual()
                || !expected.getBizCode().equals(value.path("bizCode").asText())
                || !expected.getDescription().equals(value.path("description").asText())
                || !value.path("enabled").isBoolean() || !value.path("enabled").booleanValue()
                || app && (!expected.getAppCode().equals(value.path("appCode").asText())
                    || !expected.getAppName().equals(value.path("appName").asText()) || !expected.getOwner().equals(value.path("owner").asText()))
                || !app && !expected.getBizName().equals(value.path("bizName").asText())) {
            throw new IllegalStateException("XINGYUAN_STATE_CONFLICT");
        }
        String id = requiredPublicId(value, "id");
        if (expectedId != null && !expectedId.equals(id)) { throw new IllegalStateException("XINGYUAN_STATE_CONFLICT"); }
        return id;
    }

    static com.fasterxml.jackson.databind.JsonNode nativeMetadataSelection(com.fasterxml.jackson.databind.JsonNode values,
            NativeMetadataCreateCommandDTO expected) {
        if (!values.isArray() || values.size() > 256) { throw new IllegalStateException("XINGYUAN_STATE_CONFLICT"); }
        for (var value : values) {
            if (!value.isObject() || !value.path("bizCode").isTextual() || expected.getAppCode() != null && !value.path("appCode").isTextual()) {
                throw new IllegalStateException("XINGYUAN_STATE_CONFLICT");
            }
        }
        var matches = java.util.stream.StreamSupport.stream(values.spliterator(), false)
                .filter(value -> expected.getBizCode().equals(value.path("bizCode").asText())
                        && (expected.getAppCode() == null || expected.getAppCode().equals(value.path("appCode").asText()))).toList();
        if (matches.size() > 1) { throw new IllegalStateException("XINGYUAN_STATE_CONFLICT"); }
        return matches.isEmpty() ? null : matches.getFirst();
    }

    /** Restricted transport adapter; authentication and authorization remain at the real Tianshu HTTP boundary. */
    private static com.fasterxml.jackson.databind.JsonNode nativeMetadataRequest(java.net.http.HttpClient client,
            VerifiedDatabaseInputsBO inputs, NativeMetadataCallerBO caller, String path, NativeMetadataCreateCommandDTO create, long deadline)
            throws IOException, InterruptedException {
        boolean list = path.matches("/api/v1/tianshu/(bizs|apps)\\?(keyword|bizCode)=[A-Za-z0-9_.-]{1,128}");
        boolean detail = path.matches("/api/v1/tianshu/(bizs|apps)/[A-Za-z0-9_.-]{1,128}");
        if (create == null ? !list && !detail : !path.equals("/api/v1/tianshu/" + (create.getAppCode() == null ? "bizs" : "apps"))) {
            throw new IllegalArgumentException("XINGYUAN_TARGET_UNSAFE");
        }
        var target = inputs.getManifest().getProcesses().stream().filter(process -> "tianshu".equals(process.getId())
                && "JAVA".equals(process.getKind()) && process.getPort() == 28150).toList();
        if (target.size() != 1) { throw new IllegalArgumentException("XINGYUAN_TARGET_UNSAFE"); }
        long remaining = deadline - System.nanoTime();
        if (remaining <= 0 || !caller.getExpiresAt().isAfter(Instant.now())) { throw new IllegalStateException("XINGYUAN_INPUT_EXPIRED"); }
        byte[] bytes = readProtectedBytes(Path.of(caller.getTokenFile()), Path.of(inputs.getManifest().getRuntimeRoot()).resolve("secrets"), 128 * 1024);
        try {
            if (!caller.getTokenSha256().equals(digest(bytes))) { throw new IllegalArgumentException("XINGYUAN_TARGET_UNSAFE"); }
            String token = StandardCharsets.UTF_8.newDecoder().decode(ByteBuffer.wrap(bytes)).toString();
            if (token.endsWith("\n")) { token = token.substring(0, token.length() - 1); if (token.endsWith("\r")) { token = token.substring(0, token.length() - 1); } }
            if (token.isBlank() || token.chars().anyMatch(character -> character <= 32 || character >= 127)) {
                throw new IllegalArgumentException("XINGYUAN_INPUT_INVALID");
            }
            var request = java.net.http.HttpRequest.newBuilder(java.net.URI.create("https://127.0.0.1:28150" + path))
                    .timeout(java.time.Duration.ofNanos(Math.min(remaining, java.time.Duration.ofSeconds(inputs.getManifest().getDeadlines().getHttpSeconds()).toNanos())))
                    .header("Authorization", "Bearer " + token).header("Accept", "application/json");
            if (create == null) { request.GET(); }
            else {
                try (var validators = Validation.buildDefaultValidatorFactory()) { new top.egon.cola.component.common.core.validation.ValidationUtils(validators.getValidator()).validate(create); }
                request.header("Content-Type", "application/json").POST(java.net.http.HttpRequest.BodyPublishers.ofByteArray(strictMapper().writeValueAsBytes(create)));
            }
            var output = new java.io.ByteArrayOutputStream();
            var response = client.send(request.build(), java.net.http.HttpResponse.BodyHandlers.ofByteArrayConsumer(part -> part.ifPresent(chunk -> {
                if (chunk.length > 128 * 1024 - output.size()) { throw new IllegalStateException("XINGYUAN_PARTIAL"); }
                output.writeBytes(chunk);
            })));
            return nativeMetadataData(response.statusCode(), output.toByteArray());
        } finally { Arrays.fill(bytes, (byte) 0); }
    }

    static com.fasterxml.jackson.databind.JsonNode nativeMetadataData(int statusCode, byte[] body) throws IOException {
        if (statusCode != 200 || body.length > 128 * 1024) { throw new IllegalStateException("XINGYUAN_PARTIAL"); }
        var envelope = strictMapper().readTree(body);
        if (envelope == null || !envelope.path("success").isBoolean() || !envelope.path("success").booleanValue()
                || !envelope.path("code").isIntegralNumber() || !envelope.path("code").canConvertToInt()
                || envelope.path("code").intValue() != top.egon.cola.component.common.core.enums.ResultCode.SUCCESS.getCode()
                || !envelope.path("status").isTextual() || !"SUCCESS".equals(envelope.path("status").textValue()) || !envelope.has("data")) {
            throw new IllegalStateException("XINGYUAN_PARTIAL");
        }
        return envelope.get("data");
    }

    @Test
    void nativeMetadataRequiresTheOriginalResultEnvelopeWithoutNumericTruncation() throws Exception {
        byte[] valid = strictMapper().writeValueAsBytes(top.egon.cola.component.common.core.pojo.ResultRecord.success(List.of()));
        assertThat(nativeMetadataData(200, valid).isArray()).isTrue();
        var overflow = (com.fasterxml.jackson.databind.node.ObjectNode) strictMapper().readTree(valid);
        overflow.put("code", 4294977296L);
        assertThatThrownBy(() -> nativeMetadataData(200, strictMapper().writeValueAsBytes(overflow)))
                .hasMessage("XINGYUAN_PARTIAL");
        assertThatThrownBy(() -> nativeMetadataData(302, valid)).hasMessage("XINGYUAN_PARTIAL");
        assertThatThrownBy(() -> nativeMetadataData(200, new byte[128 * 1024 + 1])).hasMessage("XINGYUAN_PARTIAL");
        overflow.put("code", 10000).put("success", false);
        assertThatThrownBy(() -> nativeMetadataData(200, strictMapper().writeValueAsBytes(overflow))).hasMessage("XINGYUAN_PARTIAL");
        for (String path : List.of("https://foreign/api/v1/tianshu/apps", "/api/v1/tianshu/apps?bizCode=owned&env=foreign",
                "/api/v1/tianshu/apps/../secret", "/api/v1/tianshu/apps", "/api/v1/tianshu/configs")) {
            assertThatThrownBy(() -> nativeMetadataRequest(null, null, null, path, null, Long.MAX_VALUE)).hasMessage("XINGYUAN_TARGET_UNSAFE");
        }
    }

    @Test
    @org.junit.jupiter.api.condition.EnabledIfEnvironmentVariable(named = "XINGYUAN_ISOLATED_INTEGRATION", matches = "true")
    void provisionNativeMetadataCatalog() throws Exception {
        Path repository = Path.of(operationProperty("xingyuan.isolated.repository-root"));
        var inputs = readVerifiedDatabaseInputs(Path.of(operationProperty("xingyuan.isolated.manifest-file")),
                Path.of(operationProperty("xingyuan.isolated.receipt-file")), repository, "rbac");
        Path root = Path.of(inputs.getManifest().getRuntimeRoot());
        Map<String, NativeCatalogPreparationBO> preparations = nativeCatalogPreparations(inputs);
        Path index = root.resolve("secrets/token-index.json");
        var caller = readNativeMetadataCaller(inputs, index);
        String marker = "xingyuan-it native:" + inputs.getManifest().getRunId() + ":" + inputs.getManifestSha256();
        Map<String, NativeMetadataCreateCommandDTO> businesses = new LinkedHashMap<>();
        Map<String, NativeMetadataCreateCommandDTO> applications = new LinkedHashMap<>();
        for (var preparation : preparations.values()) {
            var catalog = preparation.getCatalog();
            businesses.putIfAbsent(catalog.getBusinessCode(), NativeMetadataCreateCommandDTO.builder().bizCode(catalog.getBusinessCode())
                    .bizName(catalog.getBusinessCode()).description(marker).enabled(true).build());
            if (applications.putIfAbsent(catalog.getApplicationCode(), NativeMetadataCreateCommandDTO.builder().bizCode(catalog.getBusinessCode())
                    .appCode(catalog.getApplicationCode()).appName(catalog.getApplicationCode()).owner(caller.getIdentitySub())
                    .description(marker).enabled(true).build()) != null) { throw new IllegalArgumentException("XINGYUAN_INPUT_INVALID"); }
        }
        try (var validators = Validation.buildDefaultValidatorFactory()) {
            for (var commands : List.of(businesses, applications)) {
                for (var command : commands.values()) { new top.egon.cola.component.common.core.validation.ValidationUtils(validators.getValidator()).validate(command); }
            }
        }
        Path checkpoint = root.resolve("evidence/native-metadata.json");
        Path lockPath = root.resolve("evidence/native-metadata.lock");
        requirePrivateDirectory(lockPath.getParent());
        try (var channel = FileChannel.open(lockPath, Set.of(StandardOpenOption.CREATE, StandardOpenOption.WRITE, LinkOption.NOFOLLOW_LINKS),
                PosixFilePermissions.asFileAttribute(PosixFilePermissions.fromString("rw-------")))) {
            readProtectedBytes(lockPath, root.resolve("evidence"), 1024);
            try (var lock = channel.tryLock()) {
                if (lock == null) { throw new IllegalStateException("XINGYUAN_STATE_CONFLICT"); }
                byte[] previous = Files.exists(checkpoint, LinkOption.NOFOLLOW_LINKS) ? readProtectedBytes(checkpoint, root.resolve("evidence"), 128 * 1024) : null;
                NativeMetadataReceiptDTO prior = previous == null ? null : strictMapper().readValue(previous, NativeMetadataReceiptDTO.class);
                if (prior != null) {
                    try (var validators = Validation.buildDefaultValidatorFactory()) { new top.egon.cola.component.common.core.validation.ValidationUtils(validators.getValidator()).validate(prior); }
                    if (!"true".equals(operationProperty("xingyuan.isolated.resume")) || !"COMMITTED".equals(prior.getStatus())
                            || !inputs.getManifest().getRunId().equals(prior.getRunId()) || !inputs.getManifestSha256().equals(prior.getManifestSha256())
                            || prior.getRecordedAt().isAfter(Instant.now())
                            || !businesses.keySet().equals(prior.getBusinesses().keySet()) || !applications.keySet().equals(prior.getApplications().keySet())) {
                        throw new IllegalStateException("XINGYUAN_STATE_CONFLICT");
                    }
                }
                var pending = NativeMetadataReceiptDTO.builder().schemaVersion(1).runId(inputs.getManifest().getRunId())
                        .manifestSha256(inputs.getManifestSha256()).status("RUNNING").recordedAt(Instant.now()).businesses(Map.of()).applications(Map.of()).build();
                byte[] pendingBytes = strictMapper().writeValueAsBytes(pending);
                if (prior == null) { publishAuthorizationCheckpoint(checkpoint, pendingBytes, null); }
                long deadline = System.nanoTime() + java.time.Duration.ofSeconds(inputs.getManifest().getDeadlines().getOperationSeconds()).toNanos();
                try (var tls = new AnnotationConfigApplicationContext()) {
                    tls.refresh(); installTaskTls(tls, inputs);
                    try (var client = java.net.http.HttpClient.newBuilder().followRedirects(java.net.http.HttpClient.Redirect.NEVER)
                            .connectTimeout(java.time.Duration.ofSeconds(inputs.getManifest().getDeadlines().getHttpSeconds())).build()) {
                        Map<String, String> actualBusinesses = provisionNativeMetadataRecords(client, inputs, caller, index, preparations,
                                businesses, prior == null ? null : prior.getBusinesses(), deadline);
                        Map<String, String> actualApplications = provisionNativeMetadataRecords(client, inputs, caller, index, preparations,
                                applications, prior == null ? null : prior.getApplications(), deadline);
                        if (prior == null) {
                            pending.setStatus("COMMITTED").setRecordedAt(Instant.now()).setBusinesses(actualBusinesses).setApplications(actualApplications);
                            publishAuthorizationCheckpoint(checkpoint, strictMapper().writeValueAsBytes(pending), pendingBytes);
                        } else if (!MessageDigest.isEqual(previous, readProtectedBytes(checkpoint, root.resolve("evidence"), 128 * 1024))) {
                            throw new IllegalStateException("XINGYUAN_STATE_CONFLICT");
                        }
                    }
                }
            }
        }
    }

    private static Map<String, String> provisionNativeMetadataRecords(java.net.http.HttpClient client, VerifiedDatabaseInputsBO inputs,
            NativeMetadataCallerBO caller, Path index, Map<String, NativeCatalogPreparationBO> preparations,
            Map<String, NativeMetadataCreateCommandDTO> commands, Map<String, String> prior, long deadline) throws IOException, InterruptedException {
        Map<String, String> confirmed = new LinkedHashMap<>();
        for (var entry : commands.entrySet()) {
            if (System.nanoTime() >= deadline || !caller.equals(readNativeMetadataCaller(inputs, index))
                    || !preparations.equals(nativeCatalogPreparations(inputs))) { throw new IllegalStateException("XINGYUAN_STATE_CONFLICT"); }
            var command = entry.getValue();
            boolean app = command.getAppCode() != null;
            String base = "/api/v1/tianshu/" + (app ? "apps" : "bizs");
            String query = base + (app ? "?bizCode=" : "?keyword=") + command.getBizCode();
            var existing = nativeMetadataSelection(nativeMetadataRequest(client, inputs, caller, query, null, deadline), command);
            if (existing != null && prior == null || existing == null && prior != null) { throw new IllegalStateException("XINGYUAN_STATE_CONFLICT"); }
            var actual = existing == null ? nativeMetadataRequest(client, inputs, caller, base, command, deadline) : existing;
            String id = validateNativeMetadataRecord(actual, command, prior == null ? null : prior.get(entry.getKey()));
            var reread = nativeMetadataRequest(client, inputs, caller, base + "/" + (app ? id : command.getBizCode()), null, deadline);
            validateNativeMetadataRecord(reread, command, id);
            confirmed.put(entry.getKey(), id);
        }
        if (System.nanoTime() >= deadline || !caller.equals(readNativeMetadataCaller(inputs, index))
                || !preparations.equals(nativeCatalogPreparations(inputs))) { throw new IllegalStateException("XINGYUAN_STATE_CONFLICT"); }
        return Map.copyOf(confirmed);
    }

    @Test
    void nativeMetadataRecordsRejectForeignOwnershipDisabledRowsDuplicateCodesAndChangedIds() throws Exception {
        var request = NativeMetadataCreateCommandDTO.builder().bizCode("student").appCode("evaluation").appName("evaluation")
                .owner("actual-subject").description("current-task-marker").enabled(true).build();
        var record = strictMapper().readTree("{\"id\":\"1101\",\"bizCode\":\"student\",\"appCode\":\"evaluation\",\"appName\":\"evaluation\",\"owner\":\"actual-subject\",\"description\":\"current-task-marker\",\"enabled\":true}");
        assertThat(validateNativeMetadataRecord(record, request, "1101")).isEqualTo("1101");
        assertThat(nativeMetadataSelection(strictMapper().createArrayNode().add(record), request)).isEqualTo(record);
        assertThatThrownBy(() -> nativeMetadataSelection(strictMapper().createArrayNode().add(record).add(record), request)).isInstanceOf(IllegalStateException.class);
        for (String field : List.of("owner", "description", "bizCode", "appCode", "appName", "id")) {
            var changed = record.deepCopy(); ((com.fasterxml.jackson.databind.node.ObjectNode) changed).put(field, "foreign");
            assertThatThrownBy(() -> validateNativeMetadataRecord(changed, request, "1101")).isInstanceOf(RuntimeException.class);
        }
        var disabled = record.deepCopy(); ((com.fasterxml.jackson.databind.node.ObjectNode) disabled).put("enabled", false);
        assertThatThrownBy(() -> validateNativeMetadataRecord(disabled, request, "1101")).isInstanceOf(IllegalStateException.class);
        request.setBizName("invalid mixed request");
        assertThatThrownBy(() -> validateNativeMetadataRecord(record, request, "1101")).isInstanceOf(IllegalArgumentException.class);
    }

    static AnnotationConfigApplicationContext isolatedBeanContext() {
        var context = new AnnotationConfigApplicationContext();
        context.getBeanFactory().setConversionService(org.springframework.boot.convert.ApplicationConversionService.getSharedInstance());
        context.setBeanNameGenerator(new org.springframework.context.annotation.AnnotationBeanNameGenerator());
        return context;
    }





    static NativeMetadataReceiptDTO readNativeMetadataReceipt(VerifiedDatabaseInputsBO inputs,
            Map<String, NativeCatalogPreparationBO> preparations, byte[] bytes) throws IOException {
        if (bytes.length > 128 * 1024) { throw new IllegalArgumentException("XINGYUAN_INPUT_INVALID"); }
        var document = strictMapper().readTree(bytes);
        if (document == null || !document.isObject()) { throw new IllegalArgumentException("XINGYUAN_INPUT_INVALID"); }
        requireUtcInstant(requiredJsonText(document, "recordedAt", 64));
        var receipt = strictMapper().treeToValue(document, NativeMetadataReceiptDTO.class);
        try (var validators = Validation.buildDefaultValidatorFactory()) {
            new top.egon.cola.component.common.core.validation.ValidationUtils(validators.getValidator()).validate(receipt);
        }
        Set<String> businesses = preparations.values().stream().map(value -> value.getCatalog().getBusinessCode()).collect(java.util.stream.Collectors.toSet());
        Set<String> applications = preparations.values().stream().map(value -> value.getCatalog().getApplicationCode()).collect(java.util.stream.Collectors.toSet());
        if (!inputs.getManifest().getRunId().equals(receipt.getRunId()) || !inputs.getManifestSha256().equals(receipt.getManifestSha256())
                || !"COMMITTED".equals(receipt.getStatus()) || receipt.getRecordedAt().isAfter(Instant.now())
                || !businesses.equals(receipt.getBusinesses().keySet()) || !applications.equals(receipt.getApplications().keySet())) {
            throw new IllegalStateException("XINGYUAN_STATE_CONFLICT");
        }
        Set<String> identifiers = new HashSet<>();
        for (var values : List.of(receipt.getBusinesses(), receipt.getApplications())) {
            for (String id : values.values()) {
                if (!id.matches("[1-9][0-9]{0,18}") || new java.math.BigInteger(id).compareTo(java.math.BigInteger.valueOf(Long.MAX_VALUE)) > 0
                        || !identifiers.add(id)) { throw new IllegalArgumentException("XINGYUAN_TARGET_UNSAFE"); }
            }
        }
        return receipt;
    }

    static void requireNativeDirectoryBinding(NativeMetadataReceiptDTO receipt, DeploymentCatalogRegistrationCommand command,
            BusinessCatalogEntry business,
            ApplicationCatalogEntry application) {
        if (business == null || application == null || !business.enabled() || !application.businessEnabled() || !application.applicationEnabled()
                || !Objects.equals(receipt.getBusinesses().get(command.getBusinessCode()), business.ddcBusinessId())
                || !Objects.equals(receipt.getApplications().get(command.getApplicationCode()), application.ddcApplicationId())
                || !business.ddcBusinessId().equals(application.ddcBusinessId()) || !command.getBusinessCode().equals(application.bizCode())
                || !command.getBusinessCode().equals(business.bizCode()) || !command.getApplicationCode().equals(application.appCode())) {
            throw new IllegalStateException("XINGYUAN_STATE_CONFLICT");
        }
    }

    @Test
    void nativeDirectoryBindingRequiresActualIdsEnabledStateAndTheSameParentBusiness() {
        var metadata = NativeMetadataReceiptDTO.builder().businesses(Map.of("student", "501")).applications(Map.of("evaluation", "502")).build();
        var command = DeploymentCatalogRegistrationCommand.builder().businessCode("student").applicationCode("evaluation").build();
        var business = new BusinessCatalogEntry("501", "student", "Student", true);
        var application = new ApplicationCatalogEntry("502", "501", "student", "evaluation", "Evaluation", true, true);
        org.junit.jupiter.api.Assertions.assertDoesNotThrow(() -> requireNativeDirectoryBinding(metadata, command, business, application));
        for (var changed : List.of(
                new ApplicationCatalogEntry("999", "501", "student", "evaluation", "Evaluation", true, true),
                new ApplicationCatalogEntry("502", "999", "student", "evaluation", "Evaluation", true, true),
                new ApplicationCatalogEntry("502", "501", "foreign", "evaluation", "Evaluation", true, true),
                new ApplicationCatalogEntry("502", "501", "student", "evaluation", "Evaluation", false, true),
                new ApplicationCatalogEntry("502", "501", "student", "evaluation", "Evaluation", true, false))) {
            assertThatThrownBy(() -> requireNativeDirectoryBinding(metadata, command, business, changed)).hasMessage("XINGYUAN_STATE_CONFLICT");
        }
        var disabled = new BusinessCatalogEntry("501", "student", "Student", false);
        assertThatThrownBy(() -> requireNativeDirectoryBinding(metadata, command, disabled, application)).hasMessage("XINGYUAN_STATE_CONFLICT");
    }









    @Data @NoArgsConstructor @AllArgsConstructor @Accessors(chain = true) @Builder
    public static class NativeCatalogReviewReceiptDTO {
        @Min(1) @Max(1) private int schemaVersion;
        @NotBlank private String runId;
        @NotBlank @Pattern(regexp = "[0-9a-f]{64}") private String manifestSha256;
        @Min(1) private long databaseOid;
        @NotBlank @Pattern(regexp = "[0-9a-f]{64}") private String metadataSha256;
        @NotBlank @Pattern(regexp = "RUNNING|COMMITTED") private String status;
        @NotNull @com.fasterxml.jackson.annotation.JsonFormat(shape = com.fasterxml.jackson.annotation.JsonFormat.Shape.STRING) private Instant recordedAt;
        @NotNull @Size(max = 4) @jakarta.validation.Valid private Map<@NotBlank String, @NotNull DeploymentCatalogRegistrationResultVO> registrations;
        @NotNull @Size(max = 4) private Map<@NotBlank String, @NotBlank @Pattern(regexp = "[0-9a-f]{64}") String> catalogSha256;
        @NotNull @Size(max = 2) private Map<@NotBlank String, @NotBlank @Pattern(regexp = "[0-9a-f]{64}") String> scopeSha256;
    }

    static String nativeScopeSha256(Map<String, NativeCatalogPreparationBO> preparations, NativeMetadataReceiptDTO metadata,
            List<ApplicationAuthorizationScopeVO> scopes) throws IOException {
        Set<String> codes = preparations.values().stream().map(value -> value.getCatalog().getApplicationCode()).collect(java.util.stream.Collectors.toSet());
        var selected = scopes.stream().filter(scope -> codes.contains(scope.applicationCode()))
                .sorted(java.util.Comparator.comparing(ApplicationAuthorizationScopeVO::applicationCode)).toList();
        Set<String> actual = new HashSet<>(); Set<String> entitlementIds = new HashSet<>();
        for (var scope : selected) {
            var expected = preparations.values().stream().map(NativeCatalogPreparationBO::getCatalog)
                    .filter(catalog -> scope.applicationCode().equals(catalog.getApplicationCode())).findFirst().orElseThrow();
            // applicationId here is the tenant entitlement ID, never the global catalog application ID.
            if (!"ACTIVE".equals(scope.status()) || scope.version() < 0 || scope.applicationId() == null || !scope.applicationId().matches("[1-9][0-9]{0,18}")
                    || new java.math.BigInteger(scope.applicationId()).compareTo(java.math.BigInteger.valueOf(Long.MAX_VALUE)) > 0
                    || !actual.add(scope.applicationCode()) || !entitlementIds.add(scope.applicationId())
                    || !Objects.equals(metadata.getApplications().get(scope.applicationCode()), scope.ddcApplicationId())
                    || !Objects.equals(metadata.getBusinesses().get(expected.getBusinessCode()), scope.ddcBusinessId())) {
                throw new IllegalStateException("XINGYUAN_STATE_CONFLICT");
            }
        }
        if (!actual.equals(codes)) { throw new IllegalStateException("XINGYUAN_STATE_CONFLICT"); }
        return digest(strictMapper().writeValueAsBytes(selected));
    }

    private static void requireNativeDirectoryOwnership(AnnotationConfigApplicationContext context, NativeMetadataReceiptDTO metadata,
            Map<String, NativeCatalogPreparationBO> preparations) {
        var gateway = context.getBean("ddcCatalogGateway", DdcCatalogGateway.class);
        for (var preparation : preparations.values()) {
            var command = preparation.getCatalog();
            var business = gateway.findBusiness(metadata.getBusinesses().get(command.getBusinessCode()))
                    .orElseThrow(() -> new IllegalStateException("XINGYUAN_DEPENDENCY_UNAVAILABLE"));
            var application = gateway.findApplication(metadata.getApplications().get(command.getApplicationCode()))
                    .orElseThrow(() -> new IllegalStateException("XINGYUAN_DEPENDENCY_UNAVAILABLE"));
            requireNativeDirectoryBinding(metadata, command, business, application);
        }
    }

    static void validateNativeCatalogCheckpoint(NativeCatalogReviewReceiptDTO prior, VerifiedDatabaseInputsBO inputs, String metadataHash,
            Set<String> processIds, Set<String> tenants, boolean resume) {
        try (var validators = Validation.buildDefaultValidatorFactory()) {
            new top.egon.cola.component.common.core.validation.ValidationUtils(validators.getValidator()).validate(prior);
        }
        if (!resume || !"COMMITTED".equals(prior.getStatus()) || !inputs.getManifest().getRunId().equals(prior.getRunId())
                || !inputs.getManifestSha256().equals(prior.getManifestSha256()) || inputs.getReceipt().getOid() != prior.getDatabaseOid()
                || !metadataHash.equals(prior.getMetadataSha256()) || prior.getRecordedAt().isAfter(Instant.now())
                || !processIds.equals(prior.getRegistrations().keySet()) || !processIds.equals(prior.getCatalogSha256().keySet())
                || !tenants.equals(prior.getScopeSha256().keySet())) { throw new IllegalStateException("XINGYUAN_STATE_CONFLICT"); }
    }

    private static void requireCommittedPlatformAuthorization(VerifiedDatabaseInputsBO inputs, List<ResolvedPlatformBootstrapCommandDTO> commands) throws IOException {
        Path evidence = Path.of(inputs.getManifest().getRuntimeRoot()).resolve("evidence");
        var owner = strictMapper().readValue(readProtectedBytes(evidence.resolve("authorization-platform-owner.json"), evidence, 128 * 1024), PlatformAuthorizationReceiptDTO.class);
        validatePlatformCheckpoint(owner, inputs, digest(strictMapper().writeValueAsBytes(commands)), true);
        var result = strictMapper().readTree(readProtectedBytes(evidence.resolve("authorization-platform.json"), evidence, 128 * 1024));
        requireExactFields(result, Set.of("schemaVersion", "operationId", "runId", "manifestSha256", "status", "completedAt", "targets", "counts", "steps", "error"));
        if (!"COMMITTED".equals(owner.getStatus()) || !result.path("schemaVersion").isIntegralNumber()
                || !result.path("schemaVersion").canConvertToInt() || result.path("schemaVersion").intValue() != 1
                || !inputs.getManifest().getRunId().equals(result.path("runId").asText()) || !inputs.getManifestSha256().equals(result.path("manifestSha256").asText())
                || !"CLI-004".equals(result.path("operationId").asText()) || !"COMMITTED".equals(result.path("status").asText()) || !result.path("error").isNull()
                || !result.path("steps").isArray() || result.path("steps").size() != 1
                || !"PLATFORM_AUTHORIZATION".equals(result.path("steps").get(0).path("stepId").asText())
                || !"COMMITTED".equals(result.path("steps").get(0).path("state").asText())
                || !"evidence/authorization-platform-owner.json".equals(result.path("steps").get(0).path("evidence").asText())) {
            throw new IllegalStateException("XINGYUAN_STATE_CONFLICT");
        }
        requireUtcInstant(requiredJsonText(result, "completedAt", 64));
    }



    private static void requireFreshNativeCatalogs(AnnotationConfigApplicationContext context, Map<String, NativeCatalogPreparationBO> preparations,
            List<ResolvedPlatformBootstrapCommandDTO> commands) {
        Set<String> codes = preparations.values().stream().map(value -> value.getCatalog().getApplicationCode()).collect(java.util.stream.Collectors.toSet());
        if (context.getBean("globalResourceCatalogService", GlobalResourceCatalogService.class).applications().stream().anyMatch(value -> codes.contains(value.applicationCode()))) {
            throw new IllegalStateException("XINGYUAN_STATE_CONFLICT");
        }
        for (var command : commands) {
            if (context.getBean("tenantApplicationFacade", TenantApplicationFacade.class).applications(Long.valueOf(command.getTenantId())).stream()
                    .anyMatch(value -> codes.contains(value.applicationCode()))) { throw new IllegalStateException("XINGYUAN_STATE_CONFLICT"); }
        }
    }





    @Test
    void nativeCatalogInputsAndResumeRequireExactMetadataAndKeepEntitlementIdsSeparate() throws Exception {
        var manifest = intent();
        var inputs = VerifiedDatabaseInputsBO.builder().manifest(manifest).manifestSha256("b".repeat(64))
                .receipt(IsolatedDatabaseReceiptDTO.builder().oid(41).build()).build();
        Map<String, NativeCatalogPreparationBO> preparations = new LinkedHashMap<>();
        Map<String, String> businesses = new LinkedHashMap<>(); Map<String, String> applications = new LinkedHashMap<>();
        Map<String, DeploymentCatalogRegistrationResultVO> registrations = new LinkedHashMap<>();
        Map<String, String> hashes = new LinkedHashMap<>();
        List<ApplicationAuthorizationScopeVO> scopes = new java.util.ArrayList<>();
        int index = 0;
        for (String kind : List.of("light", "web", "service", "agent")) {
            String business = "business-" + kind; String application = "app-" + kind;
            businesses.put(business, Integer.toString(501 + index)); applications.put(application, Integer.toString(601 + index));
            preparations.put("native-" + kind, NativeCatalogPreparationBO.builder().catalog(DeploymentCatalogRegistrationCommand.builder()
                    .businessCode(business).applicationCode(application).build()).build());
            registrations.put("native-" + kind, new DeploymentCatalogRegistrationResultVO(Integer.toString(701 + index), application, "build", "a".repeat(64), 1, 0, 0, 0, "REGISTERED_PENDING_REVIEW"));
            hashes.put("native-" + kind, "c".repeat(64));
            scopes.add(new ApplicationAuthorizationScopeVO(Integer.toString(901 + index), Integer.toString(501 + index), Integer.toString(601 + index),
                    null, application, application, "ACTIVE", index * 10, 0));
            index++;
        }
        var metadata = NativeMetadataReceiptDTO.builder().schemaVersion(1).runId(manifest.getRunId()).manifestSha256(inputs.getManifestSha256())
                .status("COMMITTED").recordedAt(Instant.now()).businesses(businesses).applications(applications).build();
        byte[] original = strictMapper().writeValueAsBytes(metadata);
        assertThat(readNativeMetadataReceipt(inputs, preparations, original)).isEqualTo(metadata);
        assertThatThrownBy(() -> readNativeMetadataReceipt(inputs, preparations, new byte[0])).hasMessage("XINGYUAN_INPUT_INVALID");
        var nonUtc = (com.fasterxml.jackson.databind.node.ObjectNode) strictMapper().readTree(original);
        nonUtc.put("recordedAt", "2026-10-14T10:00:00+00:00");
        assertThatThrownBy(() -> readNativeMetadataReceipt(inputs, preparations, strictMapper().writeValueAsBytes(nonUtc))).hasMessage("XINGYUAN_INPUT_INVALID");
        String scopeHash = nativeScopeSha256(preparations, metadata, scopes);
        var reversed = new java.util.ArrayList<>(scopes); java.util.Collections.reverse(reversed);
        assertThat(nativeScopeSha256(preparations, metadata, reversed)).isEqualTo(scopeHash);
        assertThatThrownBy(() -> nativeScopeSha256(preparations, metadata, scopes.subList(0, 3))).hasMessage("XINGYUAN_STATE_CONFLICT");
        var duplicate = new java.util.ArrayList<>(scopes); duplicate.add(scopes.getFirst());
        assertThatThrownBy(() -> nativeScopeSha256(preparations, metadata, duplicate)).hasMessage("XINGYUAN_STATE_CONFLICT");
        metadata.setStatus("RUNNING");
        assertThatThrownBy(() -> readNativeMetadataReceipt(inputs, preparations, strictMapper().writeValueAsBytes(metadata))).hasMessage("XINGYUAN_STATE_CONFLICT");
        metadata.setStatus("COMMITTED").setApplications(Map.of("app-light", "601"));
        assertThatThrownBy(() -> readNativeMetadataReceipt(inputs, preparations, strictMapper().writeValueAsBytes(metadata))).hasMessage("XINGYUAN_STATE_CONFLICT");
        metadata.setApplications(applications).setBusinesses(new LinkedHashMap<>(businesses)); metadata.getBusinesses().put("business-light", "9223372036854775808");
        assertThatThrownBy(() -> readNativeMetadataReceipt(inputs, preparations, strictMapper().writeValueAsBytes(metadata))).hasMessage("XINGYUAN_TARGET_UNSAFE");
        var prior = NativeCatalogReviewReceiptDTO.builder().schemaVersion(1).runId(manifest.getRunId()).manifestSha256(inputs.getManifestSha256())
                .databaseOid(41).metadataSha256("a".repeat(64)).status("COMMITTED").recordedAt(Instant.now()).registrations(registrations)
                .catalogSha256(hashes).scopeSha256(Map.of("101", scopeHash, "102", scopeHash)).build();
        validateNativeCatalogCheckpoint(prior, inputs, "a".repeat(64), preparations.keySet(), Set.of("101", "102"), true);
        assertThatThrownBy(() -> validateNativeCatalogCheckpoint(prior, inputs, "a".repeat(64), preparations.keySet(), Set.of("101", "102"), false)).hasMessage("XINGYUAN_STATE_CONFLICT");
        prior.setStatus("RUNNING");
        assertThatThrownBy(() -> validateNativeCatalogCheckpoint(prior, inputs, "a".repeat(64), preparations.keySet(), Set.of("101", "102"), true)).hasMessage("XINGYUAN_STATE_CONFLICT");
        prior.setStatus("COMMITTED").setDatabaseOid(42);
        assertThatThrownBy(() -> validateNativeCatalogCheckpoint(prior, inputs, "a".repeat(64), preparations.keySet(), Set.of("101", "102"), true)).hasMessage("XINGYUAN_STATE_CONFLICT");
        prior.setDatabaseOid(41);
        assertThatThrownBy(() -> validateNativeCatalogCheckpoint(prior, inputs, "f".repeat(64), preparations.keySet(), Set.of("101", "102"), true)).hasMessage("XINGYUAN_STATE_CONFLICT");
    }

    private static void requireProvisioningProfiles(List<String> subjects, IdentityProfileDirectory.BatchResult found) {
        if (found == null || !found.available() || !found.missingSubjects().isEmpty() || !new HashSet<>(subjects).equals(found.profiles().keySet())
                || subjects.stream().anyMatch(subject -> !subject.equals(found.profiles().get(subject).subject()) || found.profiles().get(subject).version() < 0L
                || !"ACTIVE".equals(found.profiles().get(subject).status()))) { throw new IllegalStateException("XINGYUAN_DEPENDENCY_UNAVAILABLE"); }
    }

    private static List<UserPO> nativeUsers(AnnotationConfigApplicationContext context, String tenant, String subject) {
        return context.getBean("jpaSharedEM_entityManagerFactory", EntityManager.class).createQuery("""
                select user from UserEntity user where user.tenantId = :tenantId and user.identitySub = :subject
                """, UserPO.class).setParameter("tenantId", Long.valueOf(tenant)).setParameter("subject", subject).setMaxResults(2).getResultList();
    }

    private static UserPO nativeUser(AnnotationConfigApplicationContext context, String tenant, String subject) {
        var users = nativeUsers(context, tenant, subject);
        if (users.size() != 1 || !Long.valueOf(tenant).equals(users.getFirst().getTenantId()) || !subject.equals(users.getFirst().getIdentitySub())
                || users.getFirst().getStatus() != UserStatusEnum.ACTIVE || users.getFirst().getId() == null || users.getFirst().getId() <= 0L) {
            throw new IllegalStateException("XINGYUAN_STATE_CONFLICT");
        }
        return users.getFirst();
    }

    private static void requireUnprivilegedNativeActor(AnnotationConfigApplicationContext context, String tenant, UserPO user) {
        String id = user.getId().toString();
        if (!context.getBean("assignmentFacade", AssignmentFacade.class).assignments(tenant, id, Instant.now()).isEmpty()
                || !context.getBean("userBusinessAccessFacade", UserBusinessAccessFacade.class).accesses(Long.valueOf(tenant), user.getId()).isEmpty()
                || !context.getBean("roleActivationFacade", RoleActivationFacade.class).current(tenant, user.getIdentitySub(), id).activeRoles().isEmpty()) {
            throw new IllegalStateException("XINGYUAN_STATE_CONFLICT");
        }
    }

    private static NativeTenantActorsVO nativeTenantActors(AnnotationConfigApplicationContext context, String tenant,
            List<String> subjects, boolean create, Runnable guard) {
        UserPO admin = nativeUser(context, tenant, subjects.getFirst());
        if (create) {
            var users = context.getBean("userCrudFacade", UserCrudFacade.class);
            for (String subject : subjects.subList(1, 3)) {
                var command = new CreateUserCommandDTO(subject, UserStatusEnum.ACTIVE);
                try (var validators = Validation.buildDefaultValidatorFactory()) {
                    new top.egon.cola.component.common.core.validation.ValidationUtils(validators.getValidator()).validate(command);
                }
                guard.run(); var created = users.create(Long.valueOf(tenant), command, admin.getId().toString());
                guard.run(); UserPO actual = nativeUser(context, tenant, subject);
                if (!actual.getId().toString().equals(created.userId()) || !subject.equals(created.identitySub()) || !"ACTIVE".equals(created.status())
                        || actual.getAuthVersion() != created.authVersion()) { throw new IllegalStateException("XINGYUAN_PARTIAL"); }
                requireUnprivilegedNativeActor(context, tenant, actual);
            }
        }
        UserPO viewer = nativeUser(context, tenant, subjects.get(1)); UserPO provisioner = nativeUser(context, tenant, subjects.get(2));
        guard.run(); requireUnprivilegedNativeActor(context, tenant, provisioner);
        var result = new NativeTenantActorsVO(admin.getId().toString(), viewer.getId().toString(), provisioner.getId().toString());
        validateNativeTenantActorIds(result); return result;
    }

    static void validateNativeTenantActorIds(NativeTenantActorsVO actors) {
        if (actors == null || actors.adminUserId() == null || actors.viewerUserId() == null || actors.provisionerUserId() == null) { throw new IllegalStateException("XINGYUAN_STATE_CONFLICT"); }
        var ids = List.of(actors.adminUserId(), actors.viewerUserId(), actors.provisionerUserId());
        try {
            if (new HashSet<>(ids).size() != 3 || ids.stream().anyMatch(value -> !value.matches("[1-9][0-9]{0,18}") || Long.parseLong(value) <= 0L)) {
                throw new IllegalStateException("XINGYUAN_STATE_CONFLICT");
            }
        } catch (NumberFormatException invalid) { throw new IllegalStateException("XINGYUAN_STATE_CONFLICT"); }
    }

    public record NativeTenantActorsVO(@NotBlank String adminUserId, @NotBlank String viewerUserId, @NotBlank String provisionerUserId) { }

    @Data @NoArgsConstructor @AllArgsConstructor @Accessors(chain = true) @Builder
    public static class NativeActorReceiptDTO {
        @Min(1) @Max(1) private int schemaVersion;
        @NotBlank private String runId;
        @NotBlank @Pattern(regexp = "[0-9a-f]{64}") private String manifestSha256;
        @Min(1) private long databaseOid;
        @NotBlank @Pattern(regexp = "[0-9a-f]{64}") private String registrySha256;
        @NotBlank @Pattern(regexp = "[0-9a-f]{64}") private String catalogReviewSha256;
        @NotBlank @Pattern(regexp = "RUNNING|COMMITTED") private String status;
        @NotNull @com.fasterxml.jackson.annotation.JsonFormat(shape = com.fasterxml.jackson.annotation.JsonFormat.Shape.STRING) private Instant recordedAt;
        @NotNull @Size(max = 2) @Valid private Map<@NotBlank String, @NotNull NativeTenantActorsVO> actors;
    }

    static void validateNativeActorCheckpoint(NativeActorReceiptDTO prior, VerifiedDatabaseInputsBO inputs, String registryHash,
            String catalogHash, Set<String> tenants, boolean resume) {
        try (var validators = Validation.buildDefaultValidatorFactory()) {
            new top.egon.cola.component.common.core.validation.ValidationUtils(validators.getValidator()).validate(prior);
        }
        if (!resume || !"COMMITTED".equals(prior.getStatus()) || !inputs.getManifest().getRunId().equals(prior.getRunId())
                || !inputs.getManifestSha256().equals(prior.getManifestSha256()) || inputs.getReceipt().getOid() != prior.getDatabaseOid()
                || !registryHash.equals(prior.getRegistrySha256()) || !catalogHash.equals(prior.getCatalogReviewSha256())
                || prior.getRecordedAt().isAfter(Instant.now()) || !tenants.equals(prior.getActors().keySet())) { throw new IllegalStateException("XINGYUAN_STATE_CONFLICT"); }
        prior.getActors().values().forEach(IsolatedAuthorizationProvisioningIT::validateNativeTenantActorIds);
        long uniqueIds = prior.getActors().values().stream().flatMap(value -> java.util.stream.Stream.of(value.adminUserId(), value.viewerUserId(), value.provisionerUserId())).distinct().count();
        if (uniqueIds != prior.getActors().size() * 3L) { throw new IllegalStateException("XINGYUAN_STATE_CONFLICT"); }
    }



    @Test
    void nativeActorsRejectDirectoryProfileSubstitution() {
        var subjects = List.of("identity-admin", "identity-viewer", "identity-provisioner");
        Map<String, IdentityProfileDirectory.Profile> profiles = new LinkedHashMap<>();
        for (String subject : subjects) { profiles.put(subject, new IdentityProfileDirectory.Profile(subject, "profile", "Profile", "ACTIVE", 1L)); }
        org.junit.jupiter.api.Assertions.assertDoesNotThrow(() -> requireProvisioningProfiles(subjects, IdentityProfileDirectory.BatchResult.available(profiles, Set.of())));
        profiles.put("identity-provisioner", new IdentityProfileDirectory.Profile("different-identity", "profile", "Profile", "ACTIVE", 1L));
        assertThatThrownBy(() -> requireProvisioningProfiles(subjects, IdentityProfileDirectory.BatchResult.available(profiles, Set.of())))
                .hasMessage("XINGYUAN_DEPENDENCY_UNAVAILABLE");
    }

    @Test
    void nativeActorReceiptsBindTheOriginalInputsAndNeverReplayUnknownWrites() throws Exception {
        var manifest = intent();
        var inputs = VerifiedDatabaseInputsBO.builder().manifest(manifest).manifestSha256("c".repeat(64))
                .receipt(IsolatedDatabaseReceiptDTO.builder().oid(41).build()).build();
        Set<String> tenants = Set.of("1001", "1002");
        var prior = NativeActorReceiptDTO.builder().schemaVersion(1).runId(manifest.getRunId()).manifestSha256(inputs.getManifestSha256())
                .databaseOid(inputs.getReceipt().getOid()).registrySha256("a".repeat(64)).catalogReviewSha256("b".repeat(64))
                .status("COMMITTED").recordedAt(Instant.now()).actors(Map.of("1001", new NativeTenantActorsVO("301", "302", "303"),
                        "1002", new NativeTenantActorsVO("401", "402", "403"))).build();
        org.junit.jupiter.api.Assertions.assertDoesNotThrow(() -> validateNativeActorCheckpoint(prior, inputs, "a".repeat(64), "b".repeat(64), tenants, true));
        assertThatThrownBy(() -> validateNativeActorCheckpoint(prior, inputs, "a".repeat(64), "b".repeat(64), tenants, false)).hasMessage("XINGYUAN_STATE_CONFLICT");
        assertThatThrownBy(() -> validateNativeActorCheckpoint(prior, inputs, "c".repeat(64), "b".repeat(64), tenants, true)).hasMessage("XINGYUAN_STATE_CONFLICT");
        prior.setStatus("RUNNING");
        assertThatThrownBy(() -> validateNativeActorCheckpoint(prior, inputs, "a".repeat(64), "b".repeat(64), tenants, true)).hasMessage("XINGYUAN_STATE_CONFLICT");
        prior.setStatus("COMMITTED").setDatabaseOid(inputs.getReceipt().getOid() + 1L);
        assertThatThrownBy(() -> validateNativeActorCheckpoint(prior, inputs, "a".repeat(64), "b".repeat(64), tenants, true)).hasMessage("XINGYUAN_STATE_CONFLICT");
        prior.setDatabaseOid(inputs.getReceipt().getOid()).setActors(Map.of("1001", new NativeTenantActorsVO("301", "302", "303"), "1002", new NativeTenantActorsVO("301", "402", "403")));
        assertThatThrownBy(() -> validateNativeActorCheckpoint(prior, inputs, "a".repeat(64), "b".repeat(64), tenants, true)).hasMessage("XINGYUAN_STATE_CONFLICT");
        for (var invalid : List.of(new NativeTenantActorsVO("301", "301", "303"), new NativeTenantActorsVO("301", "302", "9223372036854775808"),
                new NativeTenantActorsVO("301", "302", "0"), new NativeTenantActorsVO("301", "302", null))) {
            assertThatThrownBy(() -> validateNativeTenantActorIds(invalid)).hasMessage("XINGYUAN_STATE_CONFLICT");
        }
    }

    @Test
    @SuppressWarnings("unchecked")
    void nativeActorPreparationUsesOriginalUserOwnerAndKeepsProvisionerUnprivileged() {
        var context = Mockito.mock(AnnotationConfigApplicationContext.class);
        var manager = Mockito.mock(EntityManager.class);
        jakarta.persistence.TypedQuery<UserPO> query = Mockito.mock(jakarta.persistence.TypedQuery.class, Mockito.RETURNS_SELF);
        var users = Mockito.mock(UserCrudFacade.class); var assignments = Mockito.mock(AssignmentFacade.class);
        var businesses = Mockito.mock(UserBusinessAccessFacade.class); var activation = Mockito.mock(RoleActivationFacade.class);
        Mockito.when(context.getBean("jpaSharedEM_entityManagerFactory", EntityManager.class)).thenReturn(manager);
        Mockito.when(manager.createQuery(ArgumentMatchers.anyString(), ArgumentMatchers.eq(UserPO.class))).thenReturn(query);
        Mockito.when(context.getBean("userCrudFacade", UserCrudFacade.class)).thenReturn(users);
        Mockito.when(context.getBean("assignmentFacade", AssignmentFacade.class)).thenReturn(assignments);
        Mockito.when(context.getBean("userBusinessAccessFacade", UserBusinessAccessFacade.class)).thenReturn(businesses);
        Mockito.when(context.getBean("roleActivationFacade", RoleActivationFacade.class)).thenReturn(activation);
        Instant now = Instant.parse("2026-10-15T00:00:00Z");
        var rows = new LinkedHashMap<String, UserPO>(); rows.put("identity-admin", new UserPO(301L, 1001L, "identity-admin", UserStatusEnum.ACTIVE, "301", now));
        var selected = new java.util.concurrent.atomic.AtomicReference<String>(); var nextId = new java.util.concurrent.atomic.AtomicLong(301L);
        Mockito.when(query.setParameter(ArgumentMatchers.eq("subject"), ArgumentMatchers.anyString())).thenAnswer(call -> { selected.set(call.getArgument(1)); return query; });
        Mockito.when(query.getResultList()).thenAnswer(call -> rows.containsKey(selected.get()) ? List.of(rows.get(selected.get())) : List.of());
        Mockito.when(users.create(ArgumentMatchers.eq(1001L), ArgumentMatchers.any(CreateUserCommandDTO.class), ArgumentMatchers.eq("301"))).thenAnswer(call -> {
            CreateUserCommandDTO command = call.getArgument(1); long id = nextId.incrementAndGet();
            var created = new UserPO(id, 1001L, command.identitySub(), command.status(), "301", now); rows.put(command.identitySub(), created);
            return new UserDirectoryVO(Long.toString(id), command.identitySub(), command.status().name(), created.getAuthVersion());
        });
        Mockito.when(assignments.assignments(ArgumentMatchers.eq("1001"), ArgumentMatchers.anyString(), ArgumentMatchers.any(Instant.class))).thenReturn(List.of());
        Mockito.when(businesses.accesses(ArgumentMatchers.eq(1001L), ArgumentMatchers.anyLong())).thenReturn(List.of());
        Mockito.when(activation.current(ArgumentMatchers.eq("1001"), ArgumentMatchers.anyString(), ArgumentMatchers.anyString()))
                .thenReturn(new top.egon.cola.platform.tianquan.jianshen.contract.activation.ActiveRoleSetView(List.of(), true, 1, 1, "unavailable"));
        var subjects = List.of("identity-admin", "identity-viewer", "identity-provisioner");
        var actors = nativeTenantActors(context, "1001", subjects, true, () -> { });
        assertThat(actors).isEqualTo(new NativeTenantActorsVO("301", "302", "303"));
        Mockito.verify(users, Mockito.times(2)).create(ArgumentMatchers.eq(1001L), ArgumentMatchers.any(), ArgumentMatchers.eq("301"));
        Mockito.clearInvocations(users);
        assertThat(nativeTenantActors(context, "1001", subjects, false, () -> { })).isEqualTo(actors);
        Mockito.verifyNoInteractions(users);
        Mockito.verify(assignments, Mockito.never()).assign(ArgumentMatchers.any());
        Mockito.verify(businesses, Mockito.never()).replace(ArgumentMatchers.anyLong(), ArgumentMatchers.anyLong(), ArgumentMatchers.anyString(), ArgumentMatchers.any());
        Mockito.verify(activation, Mockito.never()).replace(ArgumentMatchers.any());
        rows.put("identity-provisioner", new UserPO(301L, 1001L, "identity-provisioner", UserStatusEnum.ACTIVE, "301", now));
        assertThatThrownBy(() -> nativeTenantActors(context, "1001", subjects, false, () -> { })).hasMessage("XINGYUAN_STATE_CONFLICT");
        rows.put("identity-provisioner", new UserPO(303L, 1001L, "identity-provisioner", UserStatusEnum.ACTIVE, "301", now));
        Mockito.when(assignments.assignments(ArgumentMatchers.eq("1001"), ArgumentMatchers.eq("303"), ArgumentMatchers.any(Instant.class)))
                .thenReturn(List.of(new top.egon.cola.platform.tianquan.jianshen.admin.authorization.grant.userrole.domain.vo.AssignmentVO("501", "601", "ASSIGNED", "ACTIVE", now, null, "MANUAL", "source", 0)));
        assertThatThrownBy(() -> nativeTenantActors(context, "1001", subjects, false, () -> { })).hasMessage("XINGYUAN_STATE_CONFLICT");
        Mockito.when(assignments.assignments(ArgumentMatchers.eq("1001"), ArgumentMatchers.eq("303"), ArgumentMatchers.any(Instant.class))).thenReturn(List.of());
        Mockito.when(businesses.accesses(1001L, 303L)).thenReturn(List.of(new top.egon.cola.platform.tianquan.jianshen.admin.authorization.grant.business.domain.vo.UserBusinessAccessVO(
                "501", "303", "601", "business", "Business", "ACTIVE", now, null, "MANUAL", "source", "reason", null, 0)));
        assertThatThrownBy(() -> nativeTenantActors(context, "1001", subjects, false, () -> { })).hasMessage("XINGYUAN_STATE_CONFLICT");
        Mockito.when(businesses.accesses(1001L, 303L)).thenReturn(List.of());
        Mockito.when(activation.current("1001", "identity-provisioner", "303")).thenReturn(new top.egon.cola.platform.tianquan.jianshen.contract.activation.ActiveRoleSetView(
                List.of(new top.egon.cola.platform.tianquan.jianshen.contract.activation.ActiveRoleSetView.ApplicationActiveRoles("app", List.of("901"))), false, 1, 1, "checksum"));
        assertThatThrownBy(() -> nativeTenantActors(context, "1001", subjects, false, () -> { })).hasMessage("XINGYUAN_STATE_CONFLICT");
        Mockito.verifyNoInteractions(users);
    }

    private static String nativePolicyCode(String runId, String key) {
        if (!UUID.fromString(runId).toString().equals(runId) || !key.matches("[1-9][0-9]{0,18}:(native-(light|web|service|agent):(admin|viewer)|mcp:admin)")) {
            throw new IllegalArgumentException("XINGYUAN_TARGET_UNSAFE");
        }
        return "XINGYUAN_IT_" + runId.replace("-", "") + "_" + key.replace(':', '_').replace('-', '_').toUpperCase(java.util.Locale.ROOT);
    }

    @Data @NoArgsConstructor @AllArgsConstructor @Accessors(chain = true) @Builder
    public static class McpTaskAuthorizationReviewDTO {
        @Min(1) @Max(1) private int schemaVersion;
        @NotBlank private String runId;
        @NotBlank @Pattern(regexp = "mcp") private String processId;
        @NotNull @Size(min = 2, max = 2) private List<@NotBlank String> tenantKeys;
        @NotBlank @Pattern(regexp = "stellar-enclosure-yuheng-admin") private String applicationCode;
        @NotBlank @Pattern(regexp = "[A-Za-z0-9][A-Za-z0-9._-]{0,127}") private String businessCode;
        @NotBlank @Size(max = 128) private String permissionCode;
        @NotBlank @Size(max = 128) private String resourceCode;
        @NotBlank @Size(max = 100) private String roleCode;
        @NotBlank @Pattern(regexp = "admin") private String userKey;
        @jakarta.validation.constraints.AssertTrue private boolean approved;
    }

    static void validateMcpTaskReview(McpTaskAuthorizationReviewDTO review, String runId) {
        try (var validation = Validation.buildDefaultValidatorFactory()) { new ValidationUtils(validation.getValidator()).validate(review); }
        if (!UUID.fromString(runId).toString().equals(runId) || !runId.equals(review.getRunId()) || !List.of("default", "tenant-b").equals(review.getTenantKeys())
                || !("mcp:xingyuan-it-" + runId + ":resource:scopes:read").equals(review.getPermissionCode())
                || !("stellar-enclosure-yuheng-admin.mcp-task-" + runId.replace("-", "")).equals(review.getResourceCode())
                || !("XINGYUAN_MCP_" + runId.replace("-", "").toUpperCase(java.util.Locale.ROOT) + "_ADMIN").equals(review.getRoleCode())) {
            throw new IllegalArgumentException("XINGYUAN_TARGET_UNSAFE");
        }
    }

    private static McpTaskAuthorizationReviewDTO readMcpTaskReview(VerifiedDatabaseInputsBO inputs) throws IOException {
        Path root = Path.of(inputs.getManifest().getRuntimeRoot()), path = root.resolve("policies/mcp-authorization.json");
        var references = inputs.getManifest().getPolicyFiles().stream().filter(value -> path.toString().equals(value.getPath())).toList();
        byte[] bytes = readProtectedBytes(path, root.resolve("policies"), 128 * 1024);
        if (references.size() != 1 || !digest(bytes).equals(references.getFirst().getSha256())) { throw new IllegalArgumentException("XINGYUAN_TARGET_UNSAFE"); }
        var review = strictMapper().readValue(bytes, McpTaskAuthorizationReviewDTO.class); validateMcpTaskReview(review, inputs.getManifest().getRunId()); return review;
    }



    static DeploymentCatalogRegistrationCommand mcpTaskCatalog(McpTaskAuthorizationReviewDTO review, long applicationVersion,
            com.fasterxml.jackson.databind.ObjectMapper mapper) throws IOException {
        validateMcpTaskReview(review, review.getRunId());
        var resource = DeploymentCatalogRegistrationCommand.ResourceDefinitionBO.builder().resourceCode(review.getResourceCode()).name("Task MCP scopes read")
                .transport("REST").method("POST").path("/mcp/xingyuan-it-" + review.getRunId()).operationId("xingyuanTaskMcpScopesRead").build();
        var command = DeploymentCatalogRegistrationCommand.builder().businessCode(review.getBusinessCode()).applicationCode(review.getApplicationCode())
                .buildId("xingyuan-it-mcp-" + review.getRunId()).expectedApplicationVersion(applicationVersion)
                .permissions(List.of()).resources(List.of(resource)).fields(List.of()).build();
        var payload = new java.util.TreeMap<String, Object>(); payload.put("businessCode", command.getBusinessCode()); payload.put("applicationCode", command.getApplicationCode());
        payload.put("buildId", command.getBuildId()); payload.put("permissions", command.getPermissions()); payload.put("resources", command.getResources()); payload.put("fields", command.getFields());
        command.setChecksum(digest(mapper.copy().configure(com.fasterxml.jackson.databind.MapperFeature.SORT_PROPERTIES_ALPHABETICALLY, true)
                .configure(com.fasterxml.jackson.databind.SerializationFeature.ORDER_MAP_ENTRIES_BY_KEYS, true).writeValueAsBytes(payload)));
        try (var validation = Validation.buildDefaultValidatorFactory()) { new ValidationUtils(validation.getValidator()).validate(command, DeploymentCatalogRegistrationCommand.Registration.class); }
        return command;
    }





    private static SaveCommandDTO nativeAssignmentPolicy(String runId, String key, NativeTenantActorsVO actors, String targetId, RoleVO role, Instant now) {
        validateNativeTenantActorIds(actors);
        if (!Set.of(actors.adminUserId(), actors.viewerUserId()).contains(targetId) || actors.provisionerUserId().equals(targetId)
                || !"PUBLIC".equals(role.roleType()) || !"LOW".equals(role.riskLevel()) || role.privileged() || !"ACTIVE".equals(role.status())) {
            throw new IllegalArgumentException("XINGYUAN_TARGET_UNSAFE");
        }
        String code = nativePolicyCode(runId, key);
        if (!targetId.equals(key.endsWith(":admin") ? actors.adminUserId() : actors.viewerUserId()) || !role.roleCode().matches("XINGYUAN_[A-Z0-9_]{1,96}")) {
            throw new IllegalArgumentException("XINGYUAN_TARGET_UNSAFE");
        }
        String tenant = key.substring(0, key.indexOf(':')); Instant from = now.truncatedTo(java.time.temporal.ChronoUnit.MICROS);
        return new SaveCommandDTO(tenant, null, code, "Xingyuan isolated native assignment", from, from.plus(NATIVE_POLICY_LIFETIME),
                new ManagementPolicyRestrictionsVO(1, "LOW", "PASSWORD", true, true, false, true),
                List.of(new ManagementPolicySubjectVO("USER", actors.provisionerUserId())),
                List.of(new ManagementPolicyScopeVO("CUSTOM_USER", targetId)), List.of(role.roleId()), Set.of("ASSIGN_ROLE"), 0L, actors.adminUserId());
    }

    private static void requireNativeAssignmentPolicy(SaveCommandDTO expected, PolicyVO actual, String status) {
        if (actual == null || actual.policyId() == null || !actual.policyId().matches("[1-9][0-9]{0,18}") || actual.version() < 0
                || !status.equals(actual.status()) || !expected.policyCode().equals(actual.policyCode()) || !expected.validFrom().equals(actual.validFrom())
                || !expected.validTo().equals(actual.validTo()) || !expected.name().equals(actual.name()) || !expected.restrictions().equals(actual.restrictions())
                || !expected.subjects().equals(actual.subjects()) || !expected.scopes().equals(actual.scopes())
                || !expected.activationRootRoleIds().equals(actual.activationRootRoleIds()) || !expected.operations().equals(actual.operations())) {
            throw new IllegalStateException("XINGYUAN_STATE_CONFLICT");
        }
        try { if (Long.parseLong(actual.policyId()) <= 0L) { throw new IllegalStateException("XINGYUAN_STATE_CONFLICT"); } }
        catch (NumberFormatException invalid) { throw new IllegalStateException("XINGYUAN_STATE_CONFLICT"); }
    }

    @Test
    void nativeTemporaryPolicyRejectsBroadenedOwnerResponses() {
        Instant now = Instant.parse("2026-10-15T00:00:00Z");
        var actors = new NativeTenantActorsVO("301", "302", "303");
        var role = new RoleVO("601", "501", "XINGYUAN_NATIVE_ADMIN", "Native admin", "PUBLIC", "LOW", false, "ACTIVE", 2L);
        var command = nativeAssignmentPolicy(UUID.randomUUID().toString(), "1001:native-light:admin", actors, "301", role, now);
        var good = new PolicyVO("701", command.policyCode(), command.name(), "ACTIVE", command.validFrom(), command.validTo(), command.restrictions(),
                command.subjects(), command.scopes(), command.activationRootRoleIds(), command.operations(), 0L);
        org.junit.jupiter.api.Assertions.assertDoesNotThrow(() -> requireNativeAssignmentPolicy(command, good, "ACTIVE"));
        var broad = new PolicyVO("701", command.policyCode(), command.name(), "ACTIVE", command.validFrom(), command.validTo(), command.restrictions(),
                command.subjects(), List.of(new ManagementPolicyScopeVO("CUSTOM_USER", "999")), command.activationRootRoleIds(), Set.of("ASSIGN_ROLE", "REVOKE_ROLE"), 0L);
        assertThatThrownBy(() -> requireNativeAssignmentPolicy(command, broad, "ACTIVE")).hasMessage("XINGYUAN_STATE_CONFLICT");
    }

    @Test
    @SuppressWarnings("unchecked")
    void nativeAssignmentLifecycleDisablesOwnedPoliciesAndPreservesFailures() {
        for (String outcome : List.of("SUCCESS", "ASSIGN_UNKNOWN", "CLEANUP_FAIL", "STALE_POLICY", "EXPANDED_POLICY")) {
            var context = Mockito.mock(AnnotationConfigApplicationContext.class); var policies = Mockito.mock(ManagementPolicyFacade.class);
            var assignments = Mockito.mock(AssignmentFacade.class); var clock = Mockito.mock(DatabaseClock.class); var manager = Mockito.mock(EntityManager.class);
            jakarta.persistence.TypedQuery<UserPO> query = Mockito.mock(jakarta.persistence.TypedQuery.class, Mockito.RETURNS_SELF);
            var target = Mockito.mock(UserPO.class); var version = new java.util.concurrent.atomic.AtomicLong(1);
            Mockito.when(target.getId()).thenReturn(301L); Mockito.when(target.getTenantId()).thenReturn(1001L); Mockito.when(target.getIdentitySub()).thenReturn("identity-admin");
            Mockito.when(target.getStatus()).thenReturn(UserStatusEnum.ACTIVE); Mockito.when(target.getAuthVersion()).thenAnswer(call -> version.get());
            Mockito.when(context.getBean("jpaSharedEM_entityManagerFactory", EntityManager.class)).thenReturn(manager);
            Mockito.when(manager.createQuery(ArgumentMatchers.anyString(), ArgumentMatchers.eq(UserPO.class))).thenReturn(query);
            Mockito.when(query.getResultList()).thenReturn(List.of(target));
            Mockito.when(context.getBean("managementPolicyFacade", ManagementPolicyFacade.class)).thenReturn(policies);
            Mockito.when(context.getBean("assignmentFacade", AssignmentFacade.class)).thenReturn(assignments);
            Mockito.when(context.getBean("jpaDatabaseClock", DatabaseClock.class)).thenReturn(clock);
            Instant now = Instant.parse("2026-10-15T00:00:00Z"); Mockito.when(clock.transactionNow()).thenReturn(now);
            var state = new java.util.concurrent.atomic.AtomicReference<PolicyVO>(); var assigned = new java.util.concurrent.atomic.AtomicReference<AssignmentVO>();
            var trace = new java.util.ArrayList<String>();
            Mockito.when(policies.save(ArgumentMatchers.any())).thenAnswer(call -> {
                SaveCommandDTO command = call.getArgument(0); trace.add("save"); assertThat(MDC.get("userId")).isEqualTo("301");
                state.set(new PolicyVO("701", command.policyCode(), command.name(), "ACTIVE", command.validFrom(), command.validTo(), command.restrictions(), command.subjects(),
                        outcome.equals("EXPANDED_POLICY") ? List.of(new ManagementPolicyScopeVO("CUSTOM_USER", "999")) : command.scopes(), command.activationRootRoleIds(), command.operations(), 0L));
                return state.get();
            });
            Mockito.when(policies.policy("1001", "701")).thenAnswer(call -> state.get());
            Mockito.when(assignments.assign(ArgumentMatchers.any())).thenAnswer(call -> {
                RoleAssignmentDTO command = call.getArgument(0); trace.add("assign");
                assertThat(command.actorId()).isEqualTo("303"); assertThat(command.targetUserId()).isEqualTo("301"); assertThat(MDC.get("userId")).isEqualTo("303");
                assertThat(command.assignmentType()).isEqualTo("DIRECT"); assertThat(command.authenticationStrength()).isEqualTo("PASSWORD"); assertThat(command.platformAdministrator()).isFalse();
                assertThat(command.expectedUserAuthVersion()).isEqualTo(1L); assertThat(command.reason()).isNotBlank(); assertThat(command.ticketNo()).isEqualTo(state.get().policyCode());
                assertThat(java.time.Duration.between(command.validFrom(), command.validTo())).isEqualTo(java.time.Duration.ofHours(8));
                assigned.set(new AssignmentVO("801", command.roleId(), "DIRECT", "ACTIVE", command.validFrom(), command.validTo(), "MANAGEMENT_POLICY", "701", 0)); version.incrementAndGet();
                if (outcome.equals("ASSIGN_UNKNOWN") || outcome.equals("CLEANUP_FAIL")) { throw new IllegalStateException("XINGYUAN_COMMIT_UNKNOWN"); }
                if (outcome.equals("STALE_POLICY")) { var old = state.get(); state.set(new PolicyVO(old.policyId(), old.policyCode(), old.name(), old.status(), old.validFrom(), old.validTo(),
                        old.restrictions(), old.subjects(), old.scopes(), old.activationRootRoleIds(), old.operations(), 1L)); }
                return new AssignmentResultVO("801", "mutation", true, "COMMITTED", version.get());
            });
            Mockito.when(assignments.assignments(ArgumentMatchers.eq("1001"), ArgumentMatchers.eq("301"), ArgumentMatchers.any(Instant.class))).thenAnswer(call -> assigned.get() == null ? List.of() : List.of(assigned.get()));
            Mockito.when(policies.disable("1001", "701", 0L, "301")).thenAnswer(call -> {
                trace.add("disable"); assertThat(MDC.get("userId")).isEqualTo("301");
                if (outcome.equals("CLEANUP_FAIL")) { throw new IllegalStateException("XINGYUAN_DEPENDENCY_UNAVAILABLE"); }
                var old = state.get(); state.set(new PolicyVO(old.policyId(), old.policyCode(), old.name(), "DISABLED", old.validFrom(), old.validTo(), old.restrictions(), old.subjects(), old.scopes(),
                        old.activationRootRoleIds(), old.operations(), 1L)); return state.get();
            });
            var role = new RoleVO("601", "501", "XINGYUAN_NATIVE_ADMIN", "Native admin", "PUBLIC", "LOW", false, "ACTIVE", 2L);
            Map<String, String> previous = MDC.getCopyOfContextMap();
            try {
                MDC.put("owner-lifecycle-test", "retained"); var baseline = MDC.getCopyOfContextMap();
                if (outcome.equals("SUCCESS")) {
                    var proof = assignReviewedNativeRole(context, UUID.randomUUID().toString(), "1001:native-light:admin", new NativeTenantActorsVO("301", "302", "303"), "identity-admin", role, "a".repeat(64), () -> { });
                    assertThat(proof.assignmentId()).isEqualTo("801"); assertThat(proof.policyId()).isEqualTo("701"); assertThat(proof.authVersion()).isEqualTo(2L);
                    assertThat(proof.disabledPolicyVersion()).isEqualTo(1L); assertThat(java.time.Duration.between(proof.policyFrom(), proof.policyTo())).isEqualTo(java.time.Duration.ofMinutes(10));
                } else {
                    Throwable rejected = org.assertj.core.api.Assertions.catchThrowable(() -> assignReviewedNativeRole(context, UUID.randomUUID().toString(), "1001:native-light:admin",
                            new NativeTenantActorsVO("301", "302", "303"), "identity-admin", role, "a".repeat(64), () -> { }));
                    assertThat(rejected).hasMessage(outcome.equals("ASSIGN_UNKNOWN") || outcome.equals("CLEANUP_FAIL") ? "XINGYUAN_COMMIT_UNKNOWN" : "XINGYUAN_STATE_CONFLICT");
                    if (outcome.equals("CLEANUP_FAIL")) { assertThat(rejected.getSuppressed()).hasSize(1); assertThat(rejected.getSuppressed()[0]).hasMessage("XINGYUAN_DEPENDENCY_UNAVAILABLE"); }
                }
                assertThat(MDC.getCopyOfContextMap()).isEqualTo(baseline);
            } finally { if (previous == null) { MDC.clear(); } else { MDC.setContextMap(previous); } }
            if (outcome.equals("EXPANDED_POLICY")) { assertThat(trace).containsExactly("save"); Mockito.verify(assignments, Mockito.never()).assign(ArgumentMatchers.any()); }
            else if (outcome.equals("STALE_POLICY")) { assertThat(trace).containsExactly("save", "assign"); }
            else { assertThat(trace).containsExactly("save", "assign", "disable"); }
            if (outcome.equals("SUCCESS") || outcome.equals("ASSIGN_UNKNOWN")) { assertThat(state.get().status()).isEqualTo("DISABLED"); }
            if (!outcome.equals("EXPANDED_POLICY")) { assertThat(assigned.get()).isNotNull(); }
        }
    }

    @Test
    void nativeBusinessMergePreservesExistingManualScopeAndRejectsChangedReadbacks() {
        Instant now = Instant.parse("2026-10-15T00:00:00Z");
        var old = new UserBusinessAccessVO("701", "301", "501", "platform", "Platform", "ACTIVE", now.minusSeconds(3600), null, "MANUAL", "501", "keep", "ticket", 4L);
        var command = nativeBusinessCommand("controlled-command", List.of(old), Set.of("501", "601", "602"), now);
        assertThat(command.items()).hasSize(3);
        var retained = command.items().stream().filter(value -> value.ddcBusinessId().equals("501")).findFirst().orElseThrow();
        assertThat(retained.validFrom()).isEqualTo(old.validFrom()); assertThat(retained.reason()).isEqualTo("keep"); assertThat(retained.ticketNo()).isEqualTo("ticket"); assertThat(retained.expectedVersion()).isEqualTo(4L);
        var after = command.items().stream().map(value -> new UserBusinessAccessVO(value.ddcBusinessId().equals("501") ? "701" : "access-" + value.ddcBusinessId(), "301", value.ddcBusinessId(), "business", "Business",
                value.status().name(), value.validFrom(), value.validTo(), "MANUAL", value.ddcBusinessId(), value.reason(), value.ticketNo(), value.expectedVersion() + 1)).toList();
        org.junit.jupiter.api.Assertions.assertDoesNotThrow(() -> requireNativeBusinessReadback("301", List.of(old), command, after));
        var changed = new java.util.ArrayList<>(after); var first = changed.getFirst();
        changed.set(0, new UserBusinessAccessVO(first.accessId(), first.userId(), first.ddcBusinessId(), first.bizCode(), first.bizName(), first.status(), first.validFrom(), first.validTo(), first.sourceType(), first.sourceId(), "changed", first.ticketNo(), first.version()));
        assertThatThrownBy(() -> requireNativeBusinessReadback("301", List.of(old), command, changed)).hasMessage("XINGYUAN_PARTIAL");
        assertThatThrownBy(() -> requireNativeBusinessReadback("999", List.of(old), command, after)).hasMessage("XINGYUAN_STATE_CONFLICT");
        assertThatThrownBy(() -> nativeBusinessCommand("controlled", List.of(old, old), Set.of("601"), now)).hasMessage("XINGYUAN_STATE_CONFLICT");
        var derived = new UserBusinessAccessVO("701", "301", "501", "platform", "Platform", "ACTIVE", now, null, "ROLE", "501", "reason", null, 0L);
        assertThatThrownBy(() -> nativeBusinessCommand("controlled", List.of(derived), Set.of("601"), now)).hasMessage("XINGYUAN_STATE_CONFLICT");
    }

    @Test
    void nativeRoleReceiptsRequireAllSixteenBoundAssignmentsAndDisabledPolicyProofs() {
        var manifest = intent(); var inputs = VerifiedDatabaseInputsBO.builder().manifest(manifest).manifestSha256("c".repeat(64)).receipt(IsolatedDatabaseReceiptDTO.builder().oid(41).build()).build();
        Map<String, NativeCatalogPreparationBO> preparations = new LinkedHashMap<>();
        for (String kind : List.of("light", "web", "service", "agent")) { preparations.put("native-" + kind, NativeCatalogPreparationBO.builder().review(NativeApplicationReviewDTO.builder()
                .roles(List.of(NativeRoleReviewDTO.builder().userKey("admin").build(), NativeRoleReviewDTO.builder().userKey("viewer").build())).build()).build()); }
        var intents = nativePolicyIntents(manifest.getRunId(), preparations, Set.of("1001", "1002")); Instant now = Instant.parse("2026-10-15T00:00:00Z");
        Map<String, NativeRoleAssignmentProofVO> proofs = new LinkedHashMap<>(); long next = 501L;
        for (var entry : intents.entrySet()) { proofs.put(entry.getKey(), new NativeRoleAssignmentProofVO("301", Long.toString(next++), 2L, "a".repeat(64), Long.toString(next++), "mutation", 2L,
                Long.toString(next++), entry.getValue(), 1L, now, now.plusSeconds(600), now.plusSeconds(1), now.plusSeconds(28801))); }
        var prior = NativeRolePreparationReceiptDTO.builder().schemaVersion(1).runId(manifest.getRunId()).manifestSha256(inputs.getManifestSha256()).databaseOid(41).scope("NATIVE_ROLE_ASSIGNMENTS_ONLY")
                .registrySha256("a".repeat(64)).actorSha256("b".repeat(64)).catalogReviewSha256("d".repeat(64)).status("COMMITTED").recordedAt(Instant.now()).policyIntents(intents).assignments(proofs).build();
        org.junit.jupiter.api.Assertions.assertDoesNotThrow(() -> validateNativeRoleCheckpoint(prior, inputs, "a".repeat(64), "b".repeat(64), "d".repeat(64), intents, true));
        assertThatThrownBy(() -> validateNativeRoleCheckpoint(prior, inputs, "a".repeat(64), "b".repeat(64), "d".repeat(64), intents, false)).hasMessage("XINGYUAN_STATE_CONFLICT");
        prior.setStatus("RUNNING"); assertThatThrownBy(() -> validateNativeRoleCheckpoint(prior, inputs, "a".repeat(64), "b".repeat(64), "d".repeat(64), intents, true)).hasMessage("XINGYUAN_STATE_CONFLICT");
        prior.setStatus("COMMITTED"); assertThatThrownBy(() -> validateNativeRoleCheckpoint(prior, inputs, "a".repeat(64), "e".repeat(64), "d".repeat(64), intents, true)).hasMessage("XINGYUAN_STATE_CONFLICT");
        var incomplete = new LinkedHashMap<>(proofs); incomplete.remove(incomplete.keySet().iterator().next()); prior.setAssignments(incomplete);
        assertThatThrownBy(() -> validateNativeRoleCheckpoint(prior, inputs, "a".repeat(64), "b".repeat(64), "d".repeat(64), intents, true)).hasMessage("XINGYUAN_STATE_CONFLICT");
        var firstKey = proofs.keySet().iterator().next(); var first = proofs.get(firstKey);
        var extended = new NativeRoleAssignmentProofVO(first.userId(), first.roleId(), first.roleVersion(), first.resourceTreeSha256(), first.assignmentId(), first.mutationId(), first.authVersion(), first.policyId(), first.policyCode(), first.disabledPolicyVersion(),
                now, now.plusSeconds(601), first.assignmentFrom(), first.assignmentTo());
        var changed = new LinkedHashMap<>(proofs); changed.put(firstKey, extended); prior.setAssignments(changed);
        assertThatThrownBy(() -> validateNativeRoleCheckpoint(prior, inputs, "a".repeat(64), "b".repeat(64), "d".repeat(64), intents, true)).hasMessage("XINGYUAN_STATE_CONFLICT");
    }



    static ReplaceUserBusinessAccessesCommand nativeBusinessCommand(String commandId, List<UserBusinessAccessVO> existing, Set<String> additions, Instant now) {
        Map<String, ReplaceUserBusinessAccessesCommand.Item> desired = new LinkedHashMap<>();
        for (var access : existing) {
            if (!"MANUAL".equals(access.sourceType()) || !"ACTIVE".equals(access.status()) || access.validFrom().isAfter(now)
                    || access.validTo() != null && !access.validTo().isAfter(now) || access.version() < 0L) { throw new IllegalStateException("XINGYUAN_STATE_CONFLICT"); }
            var value = new ReplaceUserBusinessAccessesCommand.Item(access.ddcBusinessId(), UserBusinessAccessStatusEnum.ACTIVE, access.validFrom(), access.validTo(), access.reason(), access.ticketNo(), access.version());
            if (desired.putIfAbsent(access.ddcBusinessId(), value) != null) { throw new IllegalStateException("XINGYUAN_STATE_CONFLICT"); }
        }
        for (String business : new java.util.TreeSet<>(additions)) {
            desired.putIfAbsent(business, new ReplaceUserBusinessAccessesCommand.Item(business, UserBusinessAccessStatusEnum.ACTIVE, now, null, "xingyuan-it native reviewed business access", null, 0L));
        }
        return new ReplaceUserBusinessAccessesCommand(commandId, List.copyOf(desired.values()));
    }

    private static void requireNativeBusinessReadback(String userId, List<UserBusinessAccessVO> before, ReplaceUserBusinessAccessesCommand desired, List<UserBusinessAccessVO> after) {
        Map<String, UserBusinessAccessVO> actual = new LinkedHashMap<>();
        for (var access : after) { if (!userId.equals(access.userId()) || !"MANUAL".equals(access.sourceType()) || actual.putIfAbsent(access.ddcBusinessId(), access) != null) { throw new IllegalStateException("XINGYUAN_STATE_CONFLICT"); } }
        if (!actual.keySet().equals(desired.items().stream().map(ReplaceUserBusinessAccessesCommand.Item::ddcBusinessId).collect(java.util.stream.Collectors.toSet()))) { throw new IllegalStateException("XINGYUAN_PARTIAL"); }
        for (var item : desired.items()) {
            var found = actual.get(item.ddcBusinessId());
            if (!item.status().name().equals(found.status()) || !item.validFrom().equals(found.validFrom()) || !Objects.equals(item.validTo(), found.validTo())
                    || !Objects.equals(item.reason(), found.reason()) || !Objects.equals(item.ticketNo(), found.ticketNo())) { throw new IllegalStateException("XINGYUAN_PARTIAL"); }
        }
        for (var original : before) {
            var found = actual.get(original.ddcBusinessId());
            if (!original.accessId().equals(found.accessId()) || !original.userId().equals(found.userId()) || !Objects.equals(original.sourceId(), found.sourceId())
                    || found.version() < original.version()) { throw new IllegalStateException("XINGYUAN_STATE_CONFLICT"); }
        }
    }









    private static final List<String> NATIVE_FIELD_PHASES = List.of("CAP_REJECT", "EMPTY", "READ", "WRITE", "RESTORE");

    record NativeFieldRequestVO(@Min(1) @Max(1) int schemaVersion, @NotBlank String runId, @NotBlank String manifestSha256,
                                @NotBlank String nonce, @Min(1) @Max(5) int sequence, @NotBlank String phase,
                                @NotBlank @Pattern(regexp = "[0-9a-f]{64}") String previousSha256,
                                @NotNull @com.fasterxml.jackson.annotation.JsonFormat(shape = com.fasterxml.jackson.annotation.JsonFormat.Shape.STRING) Instant requestedAt,
                                @NotNull @com.fasterxml.jackson.annotation.JsonFormat(shape = com.fasterxml.jackson.annotation.JsonFormat.Shape.STRING) Instant expiresAt) { }

    record NativeFieldStateVO(@Min(0) long roleVersion, @Min(0) long policyVersion, @Min(0) long roleEventCount,
                              @NotBlank String rulesSha256) { }

    record NativeFieldSnapshotVO(@Min(0) long userAuthVersion, @Min(0) long policyVersion, @NotBlank String checksum,
                                 @Min(0) @Max(3) int missingFields, @NotNull List<FieldAccessLevel> levels) {
        NativeFieldSnapshotVO { levels = List.copyOf(levels); }
    }

    @Data @NoArgsConstructor @AllArgsConstructor @Accessors(chain = true) @Builder
    public static class NativeFieldPhaseReceiptDTO {
        @Min(1) @Max(1) private int schemaVersion;
        @NotBlank private String runId;
        @NotBlank private String manifestSha256;
        @Min(1) private long databaseOid;
        @NotBlank private String nonce;
        @Min(1) @Max(5) private int sequence;
        @NotBlank private String phase;
        @NotBlank private String previousSha256;
        @NotBlank private String status;
        @NotBlank private String tenantId;
        @NotBlank private String applicationCode;
        @NotBlank private String roleId;
        @NotNull @Valid private NativeFieldStateVO before;
        @Valid private NativeFieldStateVO after;
        @Valid private NativeFieldSnapshotVO snapshot;
        private String outcome;
        @NotNull @com.fasterxml.jackson.annotation.JsonFormat(shape = com.fasterxml.jackson.annotation.JsonFormat.Shape.STRING) private Instant recordedAt;
    }

    record NativeGrantRequestVO(@Min(1) @Max(1) int schemaVersion, @NotBlank String runId,
            @NotBlank @Pattern(regexp = "[0-9a-f]{64}") String manifestSha256, @NotBlank String nonce,
            @Min(1) @Max(2) int sequence, @NotBlank @Pattern(regexp = "REMOVE|RESTORE") String phase,
            @NotBlank @Pattern(regexp = "[0-9a-f]{64}") String previousSha256,
            @NotNull @com.fasterxml.jackson.annotation.JsonFormat(shape = com.fasterxml.jackson.annotation.JsonFormat.Shape.STRING) Instant requestedAt,
            @NotNull @com.fasterxml.jackson.annotation.JsonFormat(shape = com.fasterxml.jackson.annotation.JsonFormat.Shape.STRING) Instant expiresAt) { }

    @Data @NoArgsConstructor @AllArgsConstructor @Accessors(chain = true) @Builder
    public static class NativeGrantPhaseReceiptDTO {
        @Min(1) @Max(1) private int schemaVersion;
        @NotBlank private String runId;
        @NotBlank @Pattern(regexp = "[0-9a-f]{64}") private String manifestSha256;
        @Min(1) private long databaseOid;
        @NotBlank private String nonce;
        @Min(1) @Max(2) private int sequence;
        @NotBlank private String phase;
        @NotBlank @Pattern(regexp = "[0-9a-f]{64}") private String previousSha256;
        @NotBlank @Pattern(regexp = "RUNNING|CONFIRMED|UNKNOWN_COMMIT") private String status;
        @NotBlank private String tenantId;
        @NotBlank private String applicationCode;
        @NotBlank private String roleId;
        @NotNull @Size(min = 1, max = 2000) private List<@NotBlank String> originalResourceIds;
        @NotBlank @Pattern(regexp = "[0-9a-f]{64}") private String resourceIdsSha256;
        @NotNull @Valid private NativeFieldStateVO before;
        @Valid private NativeFieldStateVO after;
        @Valid private NativeSnapshotProofVO projection;
        private boolean resourceAllowed;
        @NotNull @com.fasterxml.jackson.annotation.JsonFormat(shape = com.fasterxml.jackson.annotation.JsonFormat.Shape.STRING) private Instant recordedAt;
    }

    static void validateNativeGrantRequest(NativeGrantRequestVO request, String runId, String digest, String nonce,
            int sequence, String previous, Instant readyAt, Instant now) {
        try (var validators = Validation.buildDefaultValidatorFactory()) { new ValidationUtils(validators.getValidator()).validate(request); }
        if (!runId.equals(request.runId()) || !digest.equals(request.manifestSha256()) || !nonce.equals(request.nonce()) || !previous.equals(request.previousSha256())
                || sequence != request.sequence() || sequence < 1 || sequence > 2 || !(sequence == 1 ? "REMOVE" : "RESTORE").equals(request.phase())
                || request.requestedAt().isBefore(readyAt) || request.requestedAt().isAfter(now) || !request.expiresAt().isAfter(now)
                || Duration.between(request.requestedAt(), request.expiresAt()).compareTo(Duration.ofSeconds(60)) > 0) {
            throw new IllegalArgumentException("XINGYUAN_TARGET_UNSAFE");
        }
    }

    @Test
    void resourceGrantRequestsCannotReplaySkipRemovalOrBroadenTheirWindow() {
        Instant now = Instant.parse("2026-10-15T00:00:00Z"); String nonce = UUID.randomUUID().toString(), digest = "a".repeat(64);
        var remove = new NativeGrantRequestVO(1, "run", digest, nonce, 1, "REMOVE", digest, now, now.plusSeconds(60));
        org.junit.jupiter.api.Assertions.assertDoesNotThrow(() -> validateNativeGrantRequest(remove, "run", digest, nonce, 1, digest, now, now));
        assertThatThrownBy(() -> validateNativeGrantRequest(remove, "run", digest, nonce, 2, digest, now, now)).hasMessage("XINGYUAN_TARGET_UNSAFE");
        assertThatThrownBy(() -> validateNativeGrantRequest(remove, "run", digest, "foreign", 1, digest, now, now)).hasMessage("XINGYUAN_TARGET_UNSAFE");
        assertThatThrownBy(() -> validateNativeGrantRequest(remove, "run", digest, nonce, 1, "b".repeat(64), now, now)).hasMessage("XINGYUAN_TARGET_UNSAFE");
        var skipped = new NativeGrantRequestVO(1, "run", digest, nonce, 1, "RESTORE", digest, now, now.plusSeconds(60));
        assertThatThrownBy(() -> validateNativeGrantRequest(skipped, "run", digest, nonce, 1, digest, now, now)).hasMessage("XINGYUAN_TARGET_UNSAFE");
        var broad = new NativeGrantRequestVO(1, "run", digest, nonce, 1, "REMOVE", digest, now, now.plusSeconds(61));
        assertThatThrownBy(() -> validateNativeGrantRequest(broad, "run", digest, nonce, 1, digest, now, now)).hasMessage("XINGYUAN_TARGET_UNSAFE");
        assertThatThrownBy(() -> validateNativeGrantRequest(remove, "run", digest, nonce, 1, digest, now, now.plusSeconds(60))).hasMessage("XINGYUAN_TARGET_UNSAFE");
    }

    static void validateNativeFieldRequest(NativeFieldRequestVO request, String runId, String manifestHash, String nonce,
                                           int sequence, String previous, Instant readyAt, Instant now) {
        try (var validators = Validation.buildDefaultValidatorFactory()) { new ValidationUtils(validators.getValidator()).validate(request); }
        if (!runId.equals(request.runId()) || !manifestHash.equals(request.manifestSha256()) || !nonce.equals(request.nonce())
                || sequence != request.sequence() || sequence < 1 || sequence > NATIVE_FIELD_PHASES.size()
                || !NATIVE_FIELD_PHASES.get(sequence - 1).equals(request.phase()) || !previous.equals(request.previousSha256())
                || request.requestedAt().isBefore(readyAt) || request.requestedAt().isAfter(now) || !request.expiresAt().isAfter(now)
                || Duration.between(request.requestedAt(), request.expiresAt()).compareTo(Duration.ofSeconds(60)) > 0) {
            throw new IllegalArgumentException("XINGYUAN_TARGET_UNSAFE");
        }
    }

    @Test
    void fieldOwnerRequestsCannotSkipPhasesReplayAnotherNonceOrOutliveTheirWindow() {
        Instant now = Instant.parse("2026-10-15T00:00:00Z"); String nonce = UUID.randomUUID().toString(), hash = "a".repeat(64);
        var request = new NativeFieldRequestVO(1, "run", hash, nonce, 1, "CAP_REJECT", hash, now, now.plusSeconds(60));
        org.junit.jupiter.api.Assertions.assertDoesNotThrow(() -> validateNativeFieldRequest(request, "run", hash, nonce, 1, hash, now, now));
        assertThatThrownBy(() -> validateNativeFieldRequest(request, "run", hash, "foreign", 1, hash, now, now)).hasMessage("XINGYUAN_TARGET_UNSAFE");
        assertThatThrownBy(() -> validateNativeFieldRequest(request, "run", hash, nonce, 2, hash, now, now)).hasMessage("XINGYUAN_TARGET_UNSAFE");
        assertThatThrownBy(() -> validateNativeFieldRequest(request, "run", hash, nonce, 1, "b".repeat(64), now, now)).hasMessage("XINGYUAN_TARGET_UNSAFE");
        assertThatThrownBy(() -> validateNativeFieldRequest(request, "run", hash, nonce, 1, hash, now, now.plusSeconds(61))).hasMessage("XINGYUAN_TARGET_UNSAFE");
        var broad = new NativeFieldRequestVO(1, "run", hash, nonce, 1, "CAP_REJECT", hash, now, now.plusSeconds(61));
        assertThatThrownBy(() -> validateNativeFieldRequest(broad, "run", hash, nonce, 1, hash, now, now)).hasMessage("XINGYUAN_TARGET_UNSAFE");
        var skipped = new NativeFieldRequestVO(1, "run", hash, nonce, 1, "WRITE", hash, now, now.plusSeconds(60));
        assertThatThrownBy(() -> validateNativeFieldRequest(skipped, "run", hash, nonce, 1, hash, now, now)).hasMessage("XINGYUAN_TARGET_UNSAFE");
    }

    private static List<top.egon.cola.platform.tianquan.jianshen.admin.authorization.policy.domain.po.FieldRulePO> nativeFieldRows(
            AnnotationConfigApplicationContext context, String tenant, String appId, String roleId) {
        return context.getBean("jpaSharedEM_entityManagerFactory", EntityManager.class).createQuery("""
                select rule from FieldRuleEntity rule where rule.tenantId = :tenant and rule.applicationId = :app and rule.roleId = :role
                order by rule.permissionId, rule.fieldDefinitionId, rule.validFrom
                """, top.egon.cola.platform.tianquan.jianshen.admin.authorization.policy.domain.po.FieldRulePO.class)
                .setParameter("tenant", Long.valueOf(tenant)).setParameter("app", Long.valueOf(appId)).setParameter("role", Long.valueOf(roleId)).getResultList();
    }



    private static top.egon.cola.platform.tianquan.jianshen.contract.authorization.UserAuthorizationSnapshot nativeRuntimeSnapshot(
            AnnotationConfigApplicationContext context, String tenant, String subject, Map<String, Set<String>> roots, Runnable guard) {
        var user = nativeUser(context, tenant, subject); var activation = context.getBean("roleActivationFacade", RoleActivationFacade.class);
        guard.run();
        var result = activation.refresh(new ReplaceCommandDTO(tenant, subject, user.getId().toString(), List.of(), user.getAuthVersion(),
                user.getId().toString(), UUID.randomUUID().toString()));
        if (result.changed() || !roots.equals(activationRoots(result.activeRoles()))) { throw new IllegalStateException("XINGYUAN_STATE_CONFLICT"); }
        guard.run();
        var record = context.getBean("postgresqlAuthorizationRuntimeRepository", PostgresqlAuthorizationRuntimeRepository.class).load(tenant, subject);
        if (record == null || !tenant.equals(record.tenantId()) || !subject.equals(record.identitySub()) || !user.getId().toString().equals(record.userId())) {
            throw new IllegalStateException("XINGYUAN_PARTIAL");
        }
        var snapshot = record.snapshot(); long policy = context.getBean("jpaTenantAuthorizationStateRepository", TenantAuthorizationStateRepository.class)
                .require(Long.valueOf(tenant)).getPolicyVersion();
        if (!snapshot.checksum().equals(result.snapshotChecksum()) || snapshot.authVersion() != nativeUser(context, tenant, subject).getAuthVersion()
                || snapshot.policyVersion() != policy || !snapshot.expiresAt().isAfter(Instant.now())) { throw new IllegalStateException("XINGYUAN_PARTIAL"); }
        return snapshot;
    }

    private static NativeFieldSnapshotVO nativeFieldSnapshot(AnnotationConfigApplicationContext context, String tenant, String subject,
            String appCode, String permission, String resource, Map<String, Set<String>> roots, Runnable guard) {
        var snapshot = nativeRuntimeSnapshot(context, tenant, subject, roots, guard);
        var apps = snapshot.appContexts().stream().filter(value -> appCode.equals(value.applicationCode())).toList();
        if (apps.size() != 1 || !apps.getFirst().permissions().contains(permission)) { throw new IllegalStateException("XINGYUAN_PARTIAL"); }
        var decision = apps.getFirst().fieldPolicies().get(permission + ':' + appCode + ':' + resource);
        List<FieldAccessLevel> observed = new java.util.ArrayList<>(); int missing = 0;
        for (String field : List.of("externalId", "name", "email")) {
            var access = decision == null ? null : decision.fields().get(field);
            if (access == null) { missing++; } else { observed.add(access.level()); }
        }
        if (decision != null && (decision.decision() != top.egon.cola.platform.tianquan.jianshen.contract.authorization.Decision.ALLOW
                || !appCode.equals(decision.applicationCode()) || !permission.equals(decision.permissionCode()) || !resource.equals(decision.resourceCode())
                || !tenant.equals(decision.tenantId()) || !snapshot.rbacUserId().equals(decision.subjectId())
                || decision.authVersion() != snapshot.authVersion() || decision.policyVersion() != snapshot.policyVersion())) {
            throw new IllegalStateException("XINGYUAN_PARTIAL");
        }
        return new NativeFieldSnapshotVO(snapshot.authVersion(), snapshot.policyVersion(), snapshot.checksum(), missing, observed);
    }

    private static Path nativeFieldEvidenceDirectory(VerifiedDatabaseInputsBO inputs) throws IOException {
        Path root = Path.of(inputs.getManifest().getRuntimeRoot()).resolve("evidence");
        Path evidence = Path.of(System.getProperty("xingyuan.isolated.evidence-directory", root.toString()));
        if (!evidence.equals(root) && (!root.equals(evidence.getParent())
                || !evidence.getFileName().toString().matches("verify-[0-9a-f]{8}(?:-[0-9a-f]{4}){3}-[0-9a-f]{12}"))) {
            throw new IllegalArgumentException("XINGYUAN_TARGET_UNSAFE");
        }
        requirePrivateDirectory(evidence); return evidence;
    }

    @Data @NoArgsConstructor @AllArgsConstructor @Accessors(chain = true) @Builder
    private static class NativeGrantOwnerBO {
        @com.fasterxml.jackson.annotation.JsonIgnore @lombok.ToString.Exclude @NotNull private AnnotationConfigApplicationContext context;
        @com.fasterxml.jackson.annotation.JsonIgnore @lombok.ToString.Exclude @NotNull private VerifiedDatabaseInputsBO inputs;
        @NotNull private Path evidence;
        @NotBlank private String tenantId;
        @NotBlank private String roleId;
        @NotBlank private String applicationId;
        @NotBlank private String applicationCode;
        @NotBlank private String permissionCode;
        @NotBlank private String resourceCode;
        @com.fasterxml.jackson.annotation.JsonIgnore @lombok.ToString.Exclude @NotBlank private String subject;
        @com.fasterxml.jackson.annotation.JsonIgnore @lombok.ToString.Exclude @NotBlank private String actorId;
        @NotNull @Size(min = 1, max = 2000) private List<@NotBlank String> resourceIds;
        @NotNull private Map<String, Set<String>> roots;
        @com.fasterxml.jackson.annotation.JsonIgnore @lombok.ToString.Exclude @NotNull private Runnable guard;
    }



    private static boolean nativeGrantResourceAllowed(top.egon.cola.platform.tianquan.jianshen.contract.authorization.UserAuthorizationSnapshot snapshot,
            String application, String permission, String resource) {
        var apps = snapshot.appContexts().stream().filter(value -> application.equals(value.applicationCode())).toList();
        if (apps.size() > 1) { throw new IllegalStateException("XINGYUAN_PARTIAL"); }
        return apps.size() == 1 && apps.getFirst().permissions().contains(permission) && apps.getFirst().resourceCodes().contains(resource);
    }





    public record NativeRoleAssignmentProofVO(
            @NotBlank String userId, @NotBlank String roleId, @Min(0) long roleVersion, @NotBlank String resourceTreeSha256,
            @NotBlank String assignmentId, @NotBlank String mutationId, @Min(1) long authVersion, @NotBlank String policyId,
            @NotBlank String policyCode, @Min(1) long disabledPolicyVersion,
            @NotNull @com.fasterxml.jackson.annotation.JsonFormat(shape = com.fasterxml.jackson.annotation.JsonFormat.Shape.STRING) Instant policyFrom,
            @NotNull @com.fasterxml.jackson.annotation.JsonFormat(shape = com.fasterxml.jackson.annotation.JsonFormat.Shape.STRING) Instant policyTo,
            @NotNull @com.fasterxml.jackson.annotation.JsonFormat(shape = com.fasterxml.jackson.annotation.JsonFormat.Shape.STRING) Instant assignmentFrom,
            @NotNull @com.fasterxml.jackson.annotation.JsonFormat(shape = com.fasterxml.jackson.annotation.JsonFormat.Shape.STRING) Instant assignmentTo) { }

    private static NativeRoleAssignmentProofVO assignReviewedNativeRole(AnnotationConfigApplicationContext context, String runId, String key,
            NativeTenantActorsVO actors, String targetSubject, RoleVO role, String treeHash, Runnable guard) {
        String tenant = key.substring(0, key.indexOf(':')); UserPO target = nativeUser(context, tenant, targetSubject);
        String targetId = key.endsWith(":admin") ? actors.adminUserId() : actors.viewerUserId();
        if (!targetId.equals(target.getId().toString()) || !treeHash.matches("[0-9a-f]{64}")) { throw new IllegalStateException("XINGYUAN_STATE_CONFLICT"); }
        var policies = context.getBean("managementPolicyFacade", ManagementPolicyFacade.class);
        var assignments = context.getBean("assignmentFacade", AssignmentFacade.class); var clock = context.getBean("jpaDatabaseClock", DatabaseClock.class);
        guard.run(); var intent = nativeAssignmentPolicy(runId, key, actors, targetId, role, clock.transactionNow());
        Map<String, String> previous = MDC.getCopyOfContextMap();
        try {
            MDC.put("tenantId", tenant); MDC.put("userId", actors.adminUserId());
            guard.run(); var saved = policies.save(intent); requireNativeAssignmentPolicy(intent, saved, "ACTIVE");
            guard.run(); var active = policies.policy(tenant, saved.policyId()); requireNativeAssignmentPolicy(intent, active, "ACTIVE");
            if (!saved.equals(active)) { throw new IllegalStateException("XINGYUAN_STATE_CONFLICT"); }
            AssignmentResultVO result = null; PolicyVO disabled = null; Instant from = null; Instant until = null; RuntimeException failure = null;
            try {
                Instant databaseNow = clock.transactionNow(); from = databaseNow.truncatedTo(java.time.temporal.ChronoUnit.MICROS); until = from.plus(NATIVE_ASSIGNMENT_LIFETIME);
                if (from.isBefore(intent.validFrom()) || !from.isBefore(intent.validTo())) { throw new IllegalStateException("XINGYUAN_DEPENDENCY_UNAVAILABLE"); }
                target = nativeUser(context, tenant, targetSubject); long expectedVersion = target.getAuthVersion();
                var request = new RoleAssignmentDTO(tenant, actors.provisionerUserId(), targetId, role.roleId(), "DIRECT", from, until,
                        "xingyuan-it reviewed native role", intent.policyCode(), "PASSWORD", false, expectedVersion, runId + ":native-assign:" + key, databaseNow);
                MDC.put("userId", actors.provisionerUserId()); guard.run(); result = assignments.assign(request);
                if (result == null || !result.completed() || result.authVersion() == null || result.authVersion() != Math.incrementExact(expectedVersion)
                        || result.mutationId() == null || result.mutationId().isBlank()) { throw new IllegalStateException("XINGYUAN_PARTIAL"); }
                guard.run(); var rows = assignments.assignments(tenant, targetId, clock.transactionNow()).stream().filter(value -> role.roleId().equals(value.roleId())).toList();
                if (rows.size() != 1 || !result.assignmentId().equals(rows.getFirst().assignmentId()) || !"DIRECT".equals(rows.getFirst().assignmentType())
                        || !"ACTIVE".equals(rows.getFirst().status()) || !from.equals(rows.getFirst().validFrom()) || !until.equals(rows.getFirst().validTo())
                        || !"MANAGEMENT_POLICY".equals(rows.getFirst().sourceType()) || !active.policyId().equals(rows.getFirst().sourceId())
                        || nativeUser(context, tenant, targetSubject).getAuthVersion() != result.authVersion()) { throw new IllegalStateException("XINGYUAN_PARTIAL"); }
            } catch (RuntimeException rejected) { failure = rejected; throw rejected; }
            finally {
                try {
                    MDC.put("userId", actors.adminUserId()); guard.run(); var current = policies.policy(tenant, active.policyId());
                    requireNativeAssignmentPolicy(intent, current, "ACTIVE");
                    if (!active.equals(current)) { throw new IllegalStateException("XINGYUAN_STATE_CONFLICT"); }
                    guard.run(); disabled = policies.disable(tenant, active.policyId(), active.version(), actors.adminUserId());
                    requireNativeAssignmentPolicy(intent, disabled, "DISABLED"); guard.run();
                    if (disabled.version() <= active.version() || !disabled.equals(policies.policy(tenant, active.policyId()))) { throw new IllegalStateException("XINGYUAN_PARTIAL"); }
                } catch (RuntimeException cleanup) { if (failure == null) { throw cleanup; } failure.addSuppressed(cleanup); }
            }
            if (result == null || disabled == null || from == null || until == null) { throw new IllegalStateException("XINGYUAN_PARTIAL"); }
            return new NativeRoleAssignmentProofVO(targetId, role.roleId(), role.version(), treeHash, result.assignmentId(), result.mutationId(), result.authVersion(),
                    disabled.policyId(), disabled.policyCode(), disabled.version(), intent.validFrom(), intent.validTo(), from, until);
        } finally { if (previous == null) { MDC.clear(); } else { MDC.setContextMap(previous); } }
    }

    @Data @NoArgsConstructor @AllArgsConstructor @Accessors(chain = true) @Builder
    public static class NativeRolePreparationReceiptDTO {
        @Min(1) @Max(1) private int schemaVersion;
        @NotBlank private String runId;
        @NotBlank @Pattern(regexp = "[0-9a-f]{64}") private String manifestSha256;
        @Min(1) private long databaseOid;
        @NotBlank @Pattern(regexp = "NATIVE_ROLE_ASSIGNMENTS_ONLY") private String scope;
        @NotBlank @Pattern(regexp = "[0-9a-f]{64}") private String registrySha256;
        @NotBlank @Pattern(regexp = "[0-9a-f]{64}") private String actorSha256;
        @NotBlank @Pattern(regexp = "[0-9a-f]{64}") private String catalogReviewSha256;
        @NotBlank @Pattern(regexp = "RUNNING|COMMITTED") private String status;
        @NotNull @com.fasterxml.jackson.annotation.JsonFormat(shape = com.fasterxml.jackson.annotation.JsonFormat.Shape.STRING) private Instant recordedAt;
        @NotNull @Size(max = 16) private Map<@NotBlank String, @NotBlank String> policyIntents;
        @NotNull @Size(max = 16) @Valid private Map<@NotBlank String, @NotNull NativeRoleAssignmentProofVO> assignments;
    }

    private static Map<String, String> nativePolicyIntents(String runId, Map<String, NativeCatalogPreparationBO> preparations, Set<String> tenants) {
        Map<String, String> expected = new java.util.TreeMap<>();
        for (var entry : preparations.entrySet()) {
            if (!entry.getValue().getReview().getRoles().stream().map(NativeRoleReviewDTO::getUserKey).collect(java.util.stream.Collectors.toSet()).equals(Set.of("admin", "viewer"))) {
                throw new IllegalArgumentException("XINGYUAN_INPUT_UNAVAILABLE");
            }
            for (String tenant : tenants) { for (String user : List.of("admin", "viewer")) {
                String key = tenant + ":" + entry.getKey() + ":" + user; expected.put(key, nativePolicyCode(runId, key));
            } }
        }
        if (expected.size() != 16) { throw new IllegalArgumentException("XINGYUAN_INPUT_UNAVAILABLE"); }
        return Map.copyOf(expected);
    }

    static void validateNativeRoleCheckpoint(NativeRolePreparationReceiptDTO prior, VerifiedDatabaseInputsBO inputs, String registryHash, String actorHash,
            String catalogHash, Map<String, String> intents, boolean resume) {
        try (var validators = Validation.buildDefaultValidatorFactory()) { new top.egon.cola.component.common.core.validation.ValidationUtils(validators.getValidator()).validate(prior); }
        if (intents.size() != 16 || new HashSet<>(intents.values()).size() != 16 || !resume || !"COMMITTED".equals(prior.getStatus()) || !inputs.getManifest().getRunId().equals(prior.getRunId()) || !inputs.getManifestSha256().equals(prior.getManifestSha256())
                || inputs.getReceipt().getOid() != prior.getDatabaseOid() || !registryHash.equals(prior.getRegistrySha256()) || !actorHash.equals(prior.getActorSha256())
                || !catalogHash.equals(prior.getCatalogReviewSha256()) || prior.getRecordedAt().isAfter(Instant.now()) || !intents.equals(prior.getPolicyIntents())
                || !intents.keySet().equals(prior.getAssignments().keySet())) { throw new IllegalStateException("XINGYUAN_STATE_CONFLICT"); }
        Set<String> roles = new HashSet<>(); Set<String> policies = new HashSet<>(); Set<String> assignments = new HashSet<>();
        for (var entry : prior.getAssignments().entrySet()) {
            var proof = entry.getValue();
            for (String id : List.of(proof.userId(), proof.roleId(), proof.policyId(), proof.assignmentId())) {
                try { if (!id.matches("[1-9][0-9]{0,18}") || Long.parseLong(id) <= 0L) { throw new IllegalStateException("XINGYUAN_STATE_CONFLICT"); } }
                catch (NumberFormatException invalid) { throw new IllegalStateException("XINGYUAN_STATE_CONFLICT"); }
            }
            if (!intents.get(entry.getKey()).equals(proof.policyCode()) || !proof.resourceTreeSha256().matches("[0-9a-f]{64}")
                    || !roles.add(proof.roleId()) || !policies.add(proof.policyId()) || !assignments.add(proof.assignmentId())
                    || !proof.policyTo().isAfter(proof.policyFrom()) || java.time.Duration.between(proof.policyFrom(), proof.policyTo()).compareTo(NATIVE_POLICY_LIFETIME) > 0
                    || proof.assignmentFrom().isBefore(proof.policyFrom()) || !proof.assignmentFrom().isBefore(proof.policyTo())
                    || !java.time.Duration.between(proof.assignmentFrom(), proof.assignmentTo()).equals(NATIVE_ASSIGNMENT_LIFETIME)) {
                throw new IllegalStateException("XINGYUAN_STATE_CONFLICT");
            }
        }
    }











    @Data @NoArgsConstructor @AllArgsConstructor @Accessors(chain = true) @Builder
    public static class NativeSnapshotProofVO {
        @NotBlank private String tenantId;
        @NotBlank @lombok.ToString.Exclude private String rbacUserId;
        @Min(1) private long authVersion;
        @Min(1) private long policyVersion;
        @NotNull @Size(min = 4, max = 8) private List<@NotBlank String> selectedRoleIds;
        @NotBlank @Pattern(regexp = "[0-9a-f]{64}") private String snapshotChecksum;
        @NotNull @com.fasterxml.jackson.annotation.JsonFormat(shape = com.fasterxml.jackson.annotation.JsonFormat.Shape.STRING) private Instant expiresAt;
    }

    @org.mapstruct.Mapper(componentModel = "spring", implementationName = "NativeSnapshotProofConverterImpl",
            uses = PlatformSnapshotProofConverter.class, unmappedTargetPolicy = org.mapstruct.ReportingPolicy.ERROR)
    public interface NativeSnapshotProofConverter extends top.egon.cola.component.common.core.converter.BaseForwardConverter<
            top.egon.cola.platform.tianquan.jianshen.contract.authorization.UserAuthorizationSnapshot, NativeSnapshotProofVO> {
        @Override
        @org.mapstruct.Mapping(target = "snapshotChecksum", source = "checksum", qualifiedByName = "canonicalSnapshotChecksum")
        @org.mapstruct.Mapping(target = "selectedRoleIds", source = "appContexts", qualifiedByName = "allRootIds")
        NativeSnapshotProofVO toTarget(top.egon.cola.platform.tianquan.jianshen.contract.authorization.UserAuthorizationSnapshot source);

        @org.mapstruct.Named("allRootIds")
        default List<String> allRootIds(List<top.egon.cola.platform.tianquan.jianshen.contract.authorization.AppAuthorizationContext> applications) {
            return applications.stream().flatMap(app -> app.activationRootRoleIds().stream()).distinct().sorted().toList();
        }
    }

    @Data @NoArgsConstructor @AllArgsConstructor @Accessors(chain = true) @Builder
    public static class NativeAuthorizationReceiptDTO {
        @Min(1) @Max(1) private int schemaVersion;
        @NotBlank private String runId;
        @NotBlank @Pattern(regexp = "[0-9a-f]{64}") private String manifestSha256;
        @Min(1) private long databaseOid;
        @NotBlank @Pattern(regexp = "native") private String phase;
        @NotBlank @Pattern(regexp = "[0-9a-f]{64}") private String registrySha256;
        @NotBlank @Pattern(regexp = "[0-9a-f]{64}") private String actorSha256;
        @NotBlank @Pattern(regexp = "[0-9a-f]{64}") private String catalogReviewSha256;
        @NotBlank @Pattern(regexp = "[0-9a-f]{64}") private String assignmentSha256;
        @NotBlank @Pattern(regexp = "RUNNING|COMMITTED") private String status;
        @NotNull @com.fasterxml.jackson.annotation.JsonFormat(shape = com.fasterxml.jackson.annotation.JsonFormat.Shape.STRING) private Instant recordedAt;
        @NotNull @Size(max = 4) @Valid private Map<@NotBlank String, @NotNull NativeSnapshotProofVO> snapshots;
    }

    static void validateNativeAuthorizationCheckpoint(NativeAuthorizationReceiptDTO receipt, VerifiedDatabaseInputsBO inputs,
            String registryHash, String actorHash, String catalogHash, String assignmentHash, NativeActorReceiptDTO actors, boolean resume) {
        try (var validators = Validation.buildDefaultValidatorFactory()) { new ValidationUtils(validators.getValidator()).validate(receipt); }
        Set<String> expected = new HashSet<>();
        actors.getActors().keySet().forEach(tenant -> { expected.add(tenant + ":admin"); expected.add(tenant + ":viewer"); });
        if (!resume || !"COMMITTED".equals(receipt.getStatus()) || !inputs.getManifest().getRunId().equals(receipt.getRunId())
                || !inputs.getManifestSha256().equals(receipt.getManifestSha256()) || inputs.getReceipt().getOid() != receipt.getDatabaseOid()
                || !registryHash.equals(receipt.getRegistrySha256()) || !actorHash.equals(receipt.getActorSha256())
                || !catalogHash.equals(receipt.getCatalogReviewSha256()) || !assignmentHash.equals(receipt.getAssignmentSha256())
                || expected.size() != 4 || !expected.equals(receipt.getSnapshots().keySet())) { throw new IllegalStateException("XINGYUAN_STATE_CONFLICT"); }
        for (var entry : receipt.getSnapshots().entrySet()) {
            String tenant = entry.getKey().substring(0, entry.getKey().indexOf(':')); boolean admin = entry.getKey().endsWith(":admin");
            var actor = actors.getActors().get(tenant); var proof = entry.getValue();
            if (!tenant.equals(proof.getTenantId()) || !(admin ? actor.adminUserId() : actor.viewerUserId()).equals(proof.getRbacUserId())
                    || proof.getSelectedRoleIds().size() != (admin ? 8 : 4)
                    || new HashSet<>(proof.getSelectedRoleIds()).size() != proof.getSelectedRoleIds().size()
                    || !proof.getExpiresAt().isAfter(Instant.now())) { throw new IllegalStateException("XINGYUAN_STATE_CONFLICT"); }
            for (String id : proof.getSelectedRoleIds()) {
                try { if (!id.matches("[1-9][0-9]{0,18}") || Long.parseLong(id) <= 0) { throw new IllegalStateException("XINGYUAN_STATE_CONFLICT"); } }
                catch (NumberFormatException invalid) { throw new IllegalStateException("XINGYUAN_STATE_CONFLICT"); }
            }
        }
    }

    @Test
    void nativeAuthorizationReceiptRequiresFourCurrentBoundSnapshotsAndExplicitResume() {
        var manifest = intent(); var inputs = VerifiedDatabaseInputsBO.builder().manifest(manifest).manifestSha256("a".repeat(64))
                .receipt(IsolatedDatabaseReceiptDTO.builder().oid(41L).build()).build();
        var actors = NativeActorReceiptDTO.builder().actors(Map.of("1001", new NativeTenantActorsVO("301", "302", "303"),
                "1002", new NativeTenantActorsVO("401", "402", "403"))).build();
        Map<String, NativeSnapshotProofVO> proofs = new LinkedHashMap<>();
        for (String tenant : actors.getActors().keySet()) { for (String key : List.of("admin", "viewer")) {
            var actor = actors.getActors().get(tenant); boolean admin = key.equals("admin");
            proofs.put(tenant + ':' + key, NativeSnapshotProofVO.builder().tenantId(tenant).rbacUserId(admin ? actor.adminUserId() : actor.viewerUserId())
                    .authVersion(5).policyVersion(7).selectedRoleIds(java.util.stream.IntStream.range(1, admin ? 9 : 5).mapToObj(Integer::toString).toList())
                    .snapshotChecksum("e".repeat(64)).expiresAt(Instant.now().plusSeconds(300)).build());
        } }
        var receipt = NativeAuthorizationReceiptDTO.builder().schemaVersion(1).runId(manifest.getRunId()).manifestSha256(inputs.getManifestSha256())
                .databaseOid(41L).phase("native").registrySha256("b".repeat(64)).actorSha256("c".repeat(64)).catalogReviewSha256("d".repeat(64))
                .assignmentSha256("f".repeat(64)).status("COMMITTED").recordedAt(Instant.now()).snapshots(proofs).build();
        Runnable validate = () -> validateNativeAuthorizationCheckpoint(receipt, inputs, "b".repeat(64), "c".repeat(64), "d".repeat(64), "f".repeat(64), actors, true);
        org.junit.jupiter.api.Assertions.assertDoesNotThrow(validate::run);
        assertThatThrownBy(() -> validateNativeAuthorizationCheckpoint(receipt, inputs, "b".repeat(64), "c".repeat(64), "d".repeat(64), "f".repeat(64), actors, false)).hasMessage("XINGYUAN_STATE_CONFLICT");
        receipt.setStatus("RUNNING"); assertThatThrownBy(validate::run).hasMessage("XINGYUAN_STATE_CONFLICT"); receipt.setStatus("COMMITTED");
        receipt.setAssignmentSha256("0".repeat(64)); assertThatThrownBy(validate::run).hasMessage("XINGYUAN_STATE_CONFLICT"); receipt.setAssignmentSha256("f".repeat(64));
        var proof = proofs.get("1001:viewer"); proof.setRbacUserId("303"); assertThatThrownBy(validate::run).hasMessage("XINGYUAN_STATE_CONFLICT"); proof.setRbacUserId("302");
        proof.setSelectedRoleIds(List.of("1", "2", "3", "3")); assertThatThrownBy(validate::run).hasMessage("XINGYUAN_STATE_CONFLICT");
        proof.setSelectedRoleIds(List.of("1", "2", "3", "9223372036854775808")); assertThatThrownBy(validate::run).hasMessage("XINGYUAN_STATE_CONFLICT");
        proof.setSelectedRoleIds(List.of("1", "2", "3", "4")); proof.setExpiresAt(Instant.now().minusSeconds(1)); assertThatThrownBy(validate::run).hasMessage("XINGYUAN_STATE_CONFLICT");
        proof.setExpiresAt(Instant.now().plusSeconds(300)); proofs.remove("1002:viewer"); assertThatThrownBy(validate::run).hasMessage("XINGYUAN_STATE_CONFLICT");
    }

    @Test
    void nativeActivationRootsRejectDuplicateApplicationsRolesAndEmptySelections() {
        var first = new top.egon.cola.platform.tianquan.jianshen.contract.activation.ActiveRoleSetView.ApplicationActiveRoles("native-a", List.of("101"));
        assertThat(activationRoots(List.of(first))).isEqualTo(Map.of("native-a", Set.of("101")));
        assertThat(activationRoots(List.of())).isEmpty();
        assertThatThrownBy(() -> activationRoots(List.of(first, first))).hasMessage("XINGYUAN_STATE_CONFLICT");
        assertThatThrownBy(() -> activationRoots(List.of(first, new top.egon.cola.platform.tianquan.jianshen.contract.activation.ActiveRoleSetView.ApplicationActiveRoles("native-b", List.of("101"))))).hasMessage("XINGYUAN_STATE_CONFLICT");
        assertThatThrownBy(() -> activationRoots(List.of(new top.egon.cola.platform.tianquan.jianshen.contract.activation.ActiveRoleSetView.ApplicationActiveRoles("native-b", List.of())))).hasMessage("XINGYUAN_STATE_CONFLICT");
    }

    @Test
    void nativeSnapshotProofUsesTheOriginalChecksumConverterAndOmitsIdentity() throws IOException {
        var snapshot = nativeApplicationSnapshotFixture().snapshot();
        try (var context = new AnnotationConfigApplicationContext(PlatformSnapshotProofConverterImpl.class, NativeSnapshotProofConverterImpl.class)) {
            var proof = context.getBean(NativeSnapshotProofConverter.class).toTarget(snapshot);
            assertThat(proof.getSnapshotChecksum()).isEqualTo(snapshot.checksum().substring("sha256:".length()));
            assertThat(proof.getSelectedRoleIds()).containsExactly("501");
            assertThat(proof.getAuthVersion()).isEqualTo(snapshot.authVersion());
            assertThat(proof.getPolicyVersion()).isEqualTo(snapshot.policyVersion());
            assertThat(strictMapper().writeValueAsString(proof)).doesNotContain(snapshot.identitySub(), "identitySub");
            assertThat(proof.toString()).doesNotContain(snapshot.rbacUserId());
        }
    }

    private static Map<String, Set<String>> activationRoots(
            List<top.egon.cola.platform.tianquan.jianshen.contract.activation.ActiveRoleSetView.ApplicationActiveRoles> applications) {
        Map<String, Set<String>> roots = new java.util.TreeMap<>(); Set<String> all = new HashSet<>();
        for (var app : applications) {
            var selected = Set.copyOf(app.rootRoleIds());
            if (selected.isEmpty() || selected.size() != app.rootRoleIds().size() || roots.putIfAbsent(app.applicationCode(), selected) != null
                    || selected.stream().anyMatch(role -> !all.add(role))) { throw new IllegalStateException("XINGYUAN_STATE_CONFLICT"); }
        }
        return Map.copyOf(roots);
    }

    private static Map<String, Set<String>> nativeActivationRoots(AnnotationConfigApplicationContext context,
            ResolvedPlatformBootstrapCommandDTO command, String userKey, String subject, Map<String, NativeCatalogFactsBO> facts,
            NativeRolePreparationReceiptDTO roles, boolean fresh) {
        UserPO user = nativeUser(context, command.getTenantId(), subject);
        var current = context.getBean("roleActivationFacade", RoleActivationFacade.class).current(command.getTenantId(), subject, user.getId().toString());
        Map<String, Set<String>> existing = activationRoots(current.activeRoles()); Map<String, Set<String>> expected = new java.util.TreeMap<>();
        if (current.authVersion() != user.getAuthVersion()) { throw new IllegalStateException("XINGYUAN_STATE_CONFLICT"); }
        if ("admin".equals(userKey)) {
            Set<String> codes = Rbac3DevelopmentTopology.applications().subList(0, 4).stream().map(value -> value.applicationCode()).collect(java.util.stream.Collectors.toSet());
            existing.forEach((code, selected) -> { if (codes.contains(code)) { expected.put(code, selected); } });
            Set<String> actualPlatform = expected.values().stream().flatMap(Set::stream).collect(java.util.stream.Collectors.toSet());
            if (!expected.keySet().equals(codes) || expected.values().stream().anyMatch(value -> value.size() != 1)
                    || !actualPlatform.equals(platformRoles(context, command).stream().map(role -> role.getId().toString()).collect(java.util.stream.Collectors.toSet()))) {
                throw new IllegalStateException("XINGYUAN_STATE_CONFLICT");
            }
        }
        if (fresh && !existing.equals(expected)) { throw new IllegalStateException("XINGYUAN_STATE_CONFLICT"); }
        for (var entry : facts.entrySet()) {
            var proof = roles.getAssignments().get(command.getTenantId() + ':' + entry.getKey() + ':' + userKey);
            if (proof == null || !proof.userId().equals(user.getId().toString()) || expected.putIfAbsent(entry.getValue().getRegistration().applicationCode(), Set.of(proof.roleId())) != null) {
                throw new IllegalStateException("XINGYUAN_STATE_CONFLICT");
            }
        }
        if (expected.size() != ("admin".equals(userKey) ? 8 : 4) || !fresh && !existing.equals(expected)) { throw new IllegalStateException("XINGYUAN_STATE_CONFLICT"); }
        return Map.copyOf(expected);
    }

    private static NativeSnapshotProofVO confirmedNativeSnapshot(AnnotationConfigApplicationContext context, String tenant, String subject, String userKey,
            Map<String, Set<String>> expectedRoots, Map<String, NativeCatalogPreparationBO> preparations, Map<String, NativeCatalogFactsBO> facts,
            NativeRolePreparationReceiptDTO roles, String returnedChecksum) {
        UserPO user = nativeUser(context, tenant, subject);
        var record = context.getBean("postgresqlAuthorizationRuntimeRepository", PostgresqlAuthorizationRuntimeRepository.class).load(tenant, subject);
        long policy = context.getBean("jpaTenantAuthorizationStateRepository", TenantAuthorizationStateRepository.class).require(Long.valueOf(tenant)).getPolicyVersion();
        if (record == null || !tenant.equals(record.tenantId()) || !subject.equals(record.identitySub()) || !user.getId().toString().equals(record.userId())) { throw new IllegalStateException("XINGYUAN_PARTIAL"); }
        var snapshot = record.snapshot();
        if (!tenant.equals(snapshot.tenantId()) || !subject.equals(snapshot.identitySub()) || !user.getId().toString().equals(snapshot.rbacUserId())
                || snapshot.authVersion() != user.getAuthVersion() || snapshot.policyVersion() != policy || !snapshot.expiresAt().isAfter(Instant.now())
                || returnedChecksum != null && !returnedChecksum.equals(snapshot.checksum())) { throw new IllegalStateException("XINGYUAN_PARTIAL"); }
        Map<String, Set<String>> actual = new java.util.TreeMap<>();
        for (var app : snapshot.appContexts()) {
            if (actual.putIfAbsent(app.applicationCode(), Set.copyOf(app.activationRootRoleIds())) != null
                    || new HashSet<>(app.activationRootRoleIds()).size() != app.activationRootRoleIds().size()) { throw new IllegalStateException("XINGYUAN_PARTIAL"); }
        }
        if (!actual.equals(expectedRoots)) { throw new IllegalStateException("XINGYUAN_PARTIAL"); }
        for (var entry : preparations.entrySet()) {
            var catalog = facts.get(entry.getKey()); var app = snapshot.appContexts().stream().filter(value -> catalog.getRegistration().applicationCode().equals(value.applicationCode())).findFirst().orElseThrow();
            validateNativeApplicationSnapshot(app, entry.getValue(), catalog, roles.getAssignments().get(tenant + ':' + entry.getKey() + ':' + userKey), snapshot, userKey);
        }
        var proof = context.getBean("nativeSnapshotProofConverterImpl", NativeSnapshotProofConverter.class).toTarget(snapshot);
        try (var validators = Validation.buildDefaultValidatorFactory()) { new ValidationUtils(validators.getValidator()).validate(proof); }
        return proof;
    }









    @Data @NoArgsConstructor @AllArgsConstructor @Accessors(chain = true) @Builder
    public static class NativeCatalogFactsBO {
        @NotNull @Valid private DeploymentCatalogRegistrationResultVO registration;
        @NotNull private Map<String, PermissionCatalogVO> permissions;
        @NotNull private Map<String, ResourceVO> resources;
        @NotNull private Map<List<String>, FieldDefinitionVO> fields;
    }

    /** File-only preflight finishes for all four applications before the first metadata or authorization mutation. */
    static Map<String, NativeCatalogPreparationBO> nativeCatalogPreparations(VerifiedDatabaseInputsBO inputs) throws IOException {
        Path root = Path.of(inputs.getManifest().getRuntimeRoot());
        Path recipePath = root.resolve("policies/native-authorization.json");
        var recipeReferences = inputs.getManifest().getPolicyFiles().stream()
                .filter(reference -> recipePath.toString().equals(reference.getPath())).toList();
        byte[] bytes = readProtectedBytes(recipePath, root, 128 * 1024);
        if (recipeReferences.size() != 1 || !digest(bytes).equals(recipeReferences.getFirst().getSha256())) {
            throw new IllegalArgumentException("XINGYUAN_TARGET_UNSAFE");
        }
        var recipe = strictMapper().readValue(bytes, NativeAuthorizationRecipeDTO.class);
        try (var validators = Validation.buildDefaultValidatorFactory()) {
            if (!validators.getValidator().validate(recipe).isEmpty()) {
                throw new IllegalArgumentException("XINGYUAN_INPUT_INVALID");
            }
        }
        if (!inputs.getManifest().getRunId().equals(recipe.getRunId())
                || !List.of("default", "tenant-b").equals(recipe.getTenantKeys())) {
            throw new IllegalArgumentException("XINGYUAN_TARGET_UNSAFE");
        }
        Map<String, NativeCatalogPreparationBO> prepared = new LinkedHashMap<>();
        Set<String> applications = new HashSet<>();
        Set<String> catalogs = new HashSet<>();
        for (var review : recipe.getApplications()) {
            var process = inputs.getManifest().getProcesses().stream()
                    .filter(item -> review.getProcessId().equals(item.getId()) && "JAVA".equals(item.getKind())).toList();
            ArtifactReferenceDTO artifact = inputs.getManifest().getArtifacts().get(review.getProcessId());
            if (process.size() != 1 || !review.getProcessId().equals(process.getFirst().getArtifactRole())
                    || artifact == null || prepared.containsKey(review.getProcessId()) || !catalogs.add(review.getCatalogFile())) {
                throw new IllegalArgumentException("XINGYUAN_TARGET_UNSAFE");
            }
            Path catalogPath = Path.of(review.getCatalogFile());
            var references = inputs.getManifest().getCatalogFiles().stream()
                    .filter(reference -> catalogPath.toString().equals(reference.getPath())).toList();
            byte[] catalogBytes = readProtectedBytes(catalogPath, root, 2 * 1024 * 1024);
            if (references.size() != 1 || !digest(catalogBytes).equals(references.getFirst().getSha256())) {
                throw new IllegalArgumentException("XINGYUAN_TARGET_UNSAFE");
            }
            var catalog = strictMapper().readValue(catalogBytes, DeploymentCatalogRegistrationCommand.class);
            validateNativeReview(review, catalog);
            if (!artifact.getBuildId().equals(catalog.getBuildId()) || !applications.add(catalog.getApplicationCode())) {
                throw new IllegalArgumentException("XINGYUAN_TARGET_UNSAFE");
            }
            prepared.put(review.getProcessId(), NativeCatalogPreparationBO.builder().review(review).catalog(catalog).build());
        }
        if (!prepared.keySet().equals(Set.of("native-light", "native-web", "native-service", "native-agent"))) {
            throw new IllegalArgumentException("XINGYUAN_INPUT_INVALID");
        }
        return java.util.Collections.unmodifiableMap(prepared);
    }

    @Test
    void nativePreparationBindsFourReviewedCatalogsToTheirOwnArtifactsAndFrozenFiles() throws Exception {
        var manifest = intent();
        Path root = Path.of(manifest.getRuntimeRoot());
        for (String directory : List.of("", "policies", "catalogs")) {
            Files.createDirectories(root.resolve(directory)); privateDirectory(root.resolve(directory));
        }
        var reviews = new java.util.ArrayList<NativeApplicationReviewDTO>();
        var references = new java.util.ArrayList<FileReferenceDTO>();
        var processes = new java.util.ArrayList<ProcessTargetDTO>();
        Map<String, ArtifactReferenceDTO> artifacts = new LinkedHashMap<>();
        for (String kind : List.of("light", "web", "service", "agent")) {
            String processId = "native-" + kind;
            String code = "sample-" + kind;
            var catalog = DeploymentCatalogRegistrationCommand.builder().businessCode("sample").applicationCode(code)
                    .buildId("build-" + kind).checksum("a".repeat(64)).expectedApplicationVersion(0L)
                    .permissions(List.of(DeploymentCatalogRegistrationCommand.PermissionDefinitionBO.builder()
                            .permissionCode(code + ":read").permissionName("Read").riskLevel("LOW").build()))
                    .resources(List.of(DeploymentCatalogRegistrationCommand.ResourceDefinitionBO.builder()
                            .resourceCode(code + ".read").name("Read").transport("REST").method("GET")
                            .path("/api/sample").operationId("readSample").build())).fields(List.of()).build();
            Path file = root.resolve("catalogs/" + kind + ".json");
            privateJson(file, catalog);
            references.add(FileReferenceDTO.builder().path(file.toString()).sha256(digest(Files.readAllBytes(file))).build());
            reviews.add(NativeApplicationReviewDTO.builder().processId(processId).catalogFile(file.toString())
                    .approvedPermissionCodes(List.of(code + ":read")).resourcePermissions(Map.of(code + ".read", code + ":read"))
                    .fields(List.of()).roles(List.of(NativeRoleReviewDTO.builder().userKey("viewer")
                            .roleCode("XINGYUAN_" + kind.toUpperCase(java.util.Locale.ROOT) + "_VIEWER")
                            .resourceCodes(List.of(code + ".read")).fieldRules(List.of()).build())).build());
            processes.add(ProcessTargetDTO.builder().id(processId).artifactRole(processId).kind("JAVA").port(28310 + processes.size()).build());
            artifacts.put(processId, ArtifactReferenceDTO.builder().path(root.resolve(kind + ".jar").toString())
                    .sha256("b".repeat(64)).buildId(catalog.getBuildId()).build());
        }
        Path recipePath = root.resolve("policies/native-authorization.json");
        var recipe = NativeAuthorizationRecipeDTO.builder().schemaVersion(1).runId(manifest.getRunId()).actorKey("admin")
                .tenantKeys(List.of("default", "tenant-b")).applications(reviews).build();
        privateJson(recipePath, recipe);
        manifest.setCatalogFiles(references).setProcesses(processes).setArtifacts(artifacts)
                .setPolicyFiles(List.of(FileReferenceDTO.builder().path(recipePath.toString())
                        .sha256(digest(Files.readAllBytes(recipePath))).build()));
        var inputs = VerifiedDatabaseInputsBO.builder().manifest(manifest).manifestSha256("c".repeat(64)).build();
        assertThat(nativeCatalogPreparations(inputs)).containsOnlyKeys("native-light", "native-web", "native-service", "native-agent");
        artifacts.get("native-light").setBuildId("another-build");
        assertThatThrownBy(() -> nativeCatalogPreparations(inputs)).isInstanceOf(IllegalArgumentException.class);
        artifacts.get("native-light").setBuildId("build-light");
        references.getFirst().setSha256("0".repeat(64));
        assertThatThrownBy(() -> nativeCatalogPreparations(inputs)).isInstanceOf(IllegalArgumentException.class);
        references.getFirst().setSha256(digest(Files.readAllBytes(Path.of(references.getFirst().getPath()))));
        recipe.setRunId(UUID.randomUUID().toString());
        Files.write(recipePath, strictMapper().writeValueAsBytes(recipe), StandardOpenOption.TRUNCATE_EXISTING);
        manifest.getPolicyFiles().getFirst().setSha256(digest(Files.readAllBytes(recipePath)));
        assertThatThrownBy(() -> nativeCatalogPreparations(inputs)).isInstanceOf(IllegalArgumentException.class);
    }

    @Data @NoArgsConstructor @AllArgsConstructor @Accessors(chain = true) @Builder
    public static class NativeAuthorizationRecipeDTO {
        @Min(1) @Max(1) private int schemaVersion;
        @NotBlank private String runId;
        @NotBlank @Pattern(regexp = "admin") private String actorKey;
        @NotNull @Size(min = 2, max = 2) private List<@NotBlank String> tenantKeys;
        @NotNull @Size(min = 4, max = 4) @Valid private List<@NotNull NativeApplicationReviewDTO> applications;
    }

    @Data @NoArgsConstructor @AllArgsConstructor @Accessors(chain = true) @Builder
    public static class NativeCatalogPreparationBO {
        @NotNull @Valid private NativeApplicationReviewDTO review;
        @NotNull @Valid private DeploymentCatalogRegistrationCommand catalog;
    }

    static void validateNativeReview(NativeApplicationReviewDTO review, DeploymentCatalogRegistrationCommand catalog) {
        try (var validators = Validation.buildDefaultValidatorFactory()) {
            Validator validator = validators.getValidator();
            if (!validator.validate(review).isEmpty()
                    || !validator.validate(catalog, DeploymentCatalogRegistrationCommand.Registration.class).isEmpty()) {
                throw new IllegalArgumentException("XINGYUAN_INPUT_INVALID");
            }
        }
        String namespace = catalog.getApplicationCode();
        if (catalog.getPermissions().stream().anyMatch(item -> !item.getPermissionCode().startsWith(namespace + ":"))
                || catalog.getResources().stream().anyMatch(item -> !item.getResourceCode().startsWith(namespace + ".")
                || item.getSuggestedPermissionCode() != null && !item.getSuggestedPermissionCode().startsWith(namespace + ":"))) {
            throw new IllegalArgumentException("XINGYUAN_INPUT_INVALID");
        }
        Set<String> permissionCodes = catalog.getPermissions().stream()
                .map(DeploymentCatalogRegistrationCommand.PermissionDefinitionBO::getPermissionCode)
                .collect(java.util.stream.Collectors.toSet());
        Set<String> resourceCodes = catalog.getResources().stream()
                .map(DeploymentCatalogRegistrationCommand.ResourceDefinitionBO::getResourceCode)
                .collect(java.util.stream.Collectors.toSet());
        Set<List<String>> declaredFields = catalog.getFields().stream()
                .map(field -> List.of(field.getResourceCode(), field.getFieldCode()))
                .collect(java.util.stream.Collectors.toSet());
        var approved = new HashSet<>(review.getApprovedPermissionCodes());
        if (approved.size() != review.getApprovedPermissionCodes().size() || !permissionCodes.containsAll(approved)
                || !resourceCodes.containsAll(review.getResourcePermissions().keySet())
                || !approved.containsAll(review.getResourcePermissions().values())) {
            throw new IllegalArgumentException("XINGYUAN_INPUT_INVALID");
        }
        Map<List<String>, NativeFieldReviewDTO> definitions = new LinkedHashMap<>();
        for (var definition : review.getFields()) {
            var key = List.of(definition.getResourceCode(), definition.getFieldCode());
            if (!declaredFields.contains(key) || definitions.putIfAbsent(key, definition) != null
                    || ("MASKED_READ".equals(definition.getDefaultAccess())
                    && (definition.getMaskingStrategy() == null || definition.getMaskingStrategy().isBlank()))) {
                throw new IllegalArgumentException("XINGYUAN_INPUT_INVALID");
            }
        }
        if (!definitions.keySet().equals(declaredFields)) { throw new IllegalArgumentException("XINGYUAN_INPUT_INVALID"); }
        Set<String> userKeys = new HashSet<>();
        Set<String> roleCodes = new HashSet<>();
        for (var role : review.getRoles()) {
            if (!userKeys.add(role.getUserKey()) || !roleCodes.add(role.getRoleCode())
                    || new HashSet<>(role.getResourceCodes()).size() != role.getResourceCodes().size()
                    || !review.getResourcePermissions().keySet().containsAll(role.getResourceCodes())) {
                throw new IllegalArgumentException("XINGYUAN_INPUT_INVALID");
            }
            Set<List<String>> ruleKeys = new HashSet<>();
            for (var rule : role.getFieldRules()) {
                var key = List.of(rule.getResourceCode(), rule.getFieldCode());
                var definition = definitions.get(key);
                if (!ruleKeys.add(key) || definition == null || !role.getResourceCodes().contains(rule.getResourceCode())
                        || ("WRITE".equals(rule.getAccessLevel()) && !definition.getWritable())
                        || ("MASKED_READ".equals(rule.getAccessLevel())
                        && (definition.getMaskingStrategy() == null || definition.getMaskingStrategy().isBlank()))) {
                    throw new IllegalArgumentException("XINGYUAN_INPUT_INVALID");
                }
            }
        }
    }

    @Test
    void nativeReviewRejectsForeignMappingsAndWritableEscalationBeforeAnyOwner() {
        var permission = DeploymentCatalogRegistrationCommand.PermissionDefinitionBO.builder()
                .permissionCode("sample:read").permissionName("Read").riskLevel("LOW").build();
        var resource = DeploymentCatalogRegistrationCommand.ResourceDefinitionBO.builder().resourceCode("sample.read")
                .name("Read").transport("REST").method("GET").path("/api/sample").operationId("readSample").build();
        var field = DeploymentCatalogRegistrationCommand.FieldDefinitionBO.builder().resourceCode("sample.read")
                .fieldCode("name").jsonPath("$.name").dataType("STRING").build();
        var catalog = DeploymentCatalogRegistrationCommand.builder().businessCode("sample").applicationCode("sample")
                .buildId("build-1").checksum("a".repeat(64)).expectedApplicationVersion(0L)
                .permissions(List.of(permission)).resources(List.of(resource)).fields(List.of(field)).build();
        var definition = NativeFieldReviewDTO.builder().resourceCode("sample.read").fieldCode("name")
                .sensitivity("NORMAL").defaultAccess("NONE").writable(false).exportable(false).build();
        var role = NativeRoleReviewDTO.builder().userKey("viewer").roleCode("XINGYUAN_VIEWER")
                .resourceCodes(List.of("sample.read")).fieldRules(List.of(NativeFieldAccessDTO.builder()
                        .resourceCode("sample.read").fieldCode("name").accessLevel("READ").build())).build();
        var review = NativeApplicationReviewDTO.builder().processId("native-light").catalogFile("catalogs/light.json")
                .approvedPermissionCodes(List.of("sample:read")).resourcePermissions(Map.of("sample.read", "sample:read"))
                .fields(List.of(definition)).roles(List.of(role)).build();
        org.junit.jupiter.api.Assertions.assertDoesNotThrow(() -> validateNativeReview(review, catalog));
        review.setResourcePermissions(Map.of("sample.read", "foreign:read"));
        assertThatThrownBy(() -> validateNativeReview(review, catalog)).isInstanceOf(IllegalArgumentException.class);
        review.setResourcePermissions(Map.of("sample.read", "sample:read"));
        role.getFieldRules().getFirst().setAccessLevel("WRITE");
        assertThatThrownBy(() -> validateNativeReview(review, catalog)).isInstanceOf(IllegalArgumentException.class);
        role.getFieldRules().getFirst().setAccessLevel("READ");
        review.setApprovedPermissionCodes(List.of());
        assertThatThrownBy(() -> validateNativeReview(review, catalog)).isInstanceOf(IllegalArgumentException.class);
        review.setApprovedPermissionCodes(List.of("sample:read"));
        definition.setDefaultAccess("WRITE");
        assertThatThrownBy(() -> validateNativeReview(review, catalog)).isInstanceOf(IllegalArgumentException.class);
    }

    @Data @NoArgsConstructor @AllArgsConstructor @Accessors(chain = true) @Builder
    public static class NativeApplicationReviewDTO {
        @NotBlank @Pattern(regexp = "native-(light|web|service|agent)") private String processId;
        @NotBlank @Size(max = 4096) private String catalogFile;
        @NotNull @Size(min = 1, max = 64) private List<@NotBlank String> approvedPermissionCodes;
        @NotNull @Size(min = 1, max = 128) private Map<@NotBlank String, @NotBlank String> resourcePermissions;
        @NotNull @Size(max = 256) @Valid private List<@NotNull NativeFieldReviewDTO> fields;
        @NotNull @Size(min = 1, max = 2) @Valid private List<@NotNull NativeRoleReviewDTO> roles;
    }

    @Data @NoArgsConstructor @AllArgsConstructor @Accessors(chain = true) @Builder
    public static class NativeFieldReviewDTO {
        @NotBlank private String resourceCode;
        @NotBlank private String fieldCode;
        @NotBlank @Pattern(regexp = "NORMAL|INTERNAL|CONFIDENTIAL|HIGH") private String sensitivity;
        @NotBlank @Pattern(regexp = "NONE|MASKED_READ|READ") private String defaultAccess;
        @Size(max = 256) private String maskingStrategy;
        @NotNull private Boolean writable;
        @NotNull private Boolean exportable;
    }

    @Data @NoArgsConstructor @AllArgsConstructor @Accessors(chain = true) @Builder
    public static class NativeRoleReviewDTO {
        @NotBlank @Pattern(regexp = "admin|viewer") private String userKey;
        @NotBlank @Pattern(regexp = "XINGYUAN_[A-Z0-9_]{1,96}") private String roleCode;
        @NotNull @Size(min = 1, max = 128) private List<@NotBlank String> resourceCodes;
        @NotNull @Size(max = 256) @Valid private List<@NotNull NativeFieldAccessDTO> fieldRules;
    }

    @Data @NoArgsConstructor @AllArgsConstructor @Accessors(chain = true) @Builder
    public static class NativeFieldAccessDTO {
        @NotBlank private String resourceCode;
        @NotBlank private String fieldCode;
        @NotBlank @Pattern(regexp = "NONE|MASKED_READ|READ|WRITE") private String accessLevel;
    }

    private static void requireExactFields(com.fasterxml.jackson.databind.JsonNode value, Set<String> fields) {
        if (!value.isObject() || value.size() != fields.size()) { throw new IllegalArgumentException("XINGYUAN_INPUT_INVALID"); }
        var names = value.fieldNames();
        while (names.hasNext()) { if (!fields.contains(names.next())) { throw new IllegalArgumentException("XINGYUAN_INPUT_INVALID"); } }
    }

    private static String requiredJsonText(com.fasterxml.jackson.databind.JsonNode value, String field, int maximum) {
        var item = value.path(field);
        if (!item.isTextual() || item.textValue().isBlank() || item.textValue().length() > maximum) {
            throw new IllegalArgumentException("XINGYUAN_INPUT_INVALID");
        }
        return item.textValue();
    }

    private static String requiredPublicId(com.fasterxml.jackson.databind.JsonNode value, String field) {
        String id = requiredJsonText(value, field, 19);
        try {
            if (!id.matches("[1-9][0-9]{0,18}") || Long.parseLong(id) <= 0L) {
                throw new IllegalArgumentException("XINGYUAN_INPUT_INVALID");
            }
        } catch (NumberFormatException invalid) { throw new IllegalArgumentException("XINGYUAN_INPUT_INVALID"); }
        return id;
    }

    private static void requireUtcInstant(String value) {
        try {
            if (!value.endsWith("Z")) { throw new IllegalArgumentException("XINGYUAN_INPUT_INVALID"); }
            java.time.Instant.parse(value);
        } catch (java.time.format.DateTimeParseException invalid) { throw new IllegalArgumentException("XINGYUAN_INPUT_INVALID"); }
    }

    private static String digest(byte[] bytes) {
        try { return HexFormat.of().formatHex(MessageDigest.getInstance("SHA-256").digest(bytes)); }
        catch (NoSuchAlgorithmException unavailable) { throw new IllegalStateException("XINGYUAN_INPUT_UNAVAILABLE"); }
    }

    @Test
    void platformCommandsUseTheCommittedCatalogAndActualTwoTenantIdentities() throws Exception {
        var inputs = platformInputs();
        var commands = platformBootstrapCommands(inputs);
        assertThat(commands).hasSize(2);
        assertThat(commands).extracting(ResolvedPlatformBootstrapCommandDTO::getTenantId).containsExactly("1001", "1002");
        assertThat(commands).allSatisfy(command -> {
            assertThat(command.getIdentitySub()).isEqualTo("controlled-actual-admin");
            assertThat(command.getApplications()).hasSize(4);
            assertThat(command.getApplications()).extracting(PlatformCatalogBindingDTO::getDdcApplicationId)
                    .containsExactly("7001", "7002", "7003", "7004");
        });
    }

    @Test
    void aCatalogWithForeignOwnershipOrInactiveOrConflictingFactsCannotCreateCommands() throws Exception {
        for (String mutation : List.of("inactive", "foreign-owner", "other-business", "duplicate-id", "foreign-oid", "unknown-field")) {
            var inputs = platformInputs();
            Path file = Path.of(inputs.getManifest().getRuntimeRoot()).resolve("evidence/tianshu-platform-catalog.json");
            var catalog = (com.fasterxml.jackson.databind.node.ObjectNode) strictMapper().readTree(Files.readAllBytes(file));
            var app = (com.fasterxml.jackson.databind.node.ObjectNode) catalog.path("applications").path("tianquan-jianshen-admin");
            switch (mutation) {
                case "inactive" -> app.put("enabled", false);
                case "foreign-owner" -> app.put("owner", "another-owner");
                case "other-business" -> app.put("bizCode", "platform");
                case "duplicate-id" -> app.put("id", "7002");
                case "foreign-oid" -> catalog.put("databaseOid", 999L);
                case "unknown-field" -> app.put("trusted", true);
                default -> throw new AssertionError("unknown controlled mutation");
            }
            Files.write(file, strictMapper().writeValueAsBytes(catalog), StandardOpenOption.TRUNCATE_EXISTING);
            assertThatThrownBy(() -> platformBootstrapCommands(inputs)).isInstanceOf(IllegalArgumentException.class);
        }
    }

    @Test
    void platformCommandsRejectAChangedRegistryAndUncommittedControlPlane() throws Exception {
        var inputs = platformInputs();
        Path root = Path.of(inputs.getManifest().getRuntimeRoot());
        Path registryFile = root.resolve("secrets/runtime-registry.json");
        byte[] original = Files.readAllBytes(registryFile);
        var registry = (com.fasterxml.jackson.databind.node.ObjectNode) strictMapper().readTree(original);
        ((com.fasterxml.jackson.databind.node.ObjectNode) registry.path("tenantIds")).put("tenant-b", "9999");
        Files.write(registryFile, strictMapper().writeValueAsBytes(registry), StandardOpenOption.TRUNCATE_EXISTING);
        assertThatThrownBy(() -> platformBootstrapCommands(inputs)).isInstanceOf(IllegalArgumentException.class);
        Files.write(registryFile, original, StandardOpenOption.TRUNCATE_EXISTING);
        Path controlFile = root.resolve("evidence/control-plane.json");
        var control = (com.fasterxml.jackson.databind.node.ObjectNode) strictMapper().readTree(Files.readAllBytes(controlFile));
        control.put("status", "PARTIAL");
        Files.write(controlFile, strictMapper().writeValueAsBytes(control), StandardOpenOption.TRUNCATE_EXISTING);
        assertThatThrownBy(() -> platformBootstrapCommands(inputs)).isInstanceOf(IllegalArgumentException.class);
    }

    private VerifiedDatabaseInputsBO platformInputs() throws Exception {
        var manifest = intent();
        Path root = Path.of(manifest.getRuntimeRoot());
        for (String directory : List.of("", "evidence", "secrets", "policies")) {
            Path path = root.resolve(directory);
            Files.createDirectories(path);
            privateDirectory(path);
        }
        List<String> appCodes = List.of("tianquan-jianshen-admin", "tianquan-shoubing-admin", "stellar-enclosure-yuheng-admin", "tianshu-admin");
        List<String> bizCodes = List.of("permission", "identity", "platform", "platform");
        List<String> businessCodes = List.of("permission", "identity", "platform");
        Path recipe = root.resolve("policies/platform-catalog.json");
        privateJson(recipe, Map.of("schemaVersion", 1, "runId", manifest.getRunId(), "tenantKey", "default", "actorKey", "admin",
                "businesses", businessCodes.stream().map(code -> Map.of("bizCode", code, "bizName", code)).toList(),
                "applications", java.util.stream.IntStream.range(0, 4).mapToObj(i -> Map.of("appCode", appCodes.get(i),
                        "appName", appCodes.get(i), "bizCode", bizCodes.get(i))).toList()));
        manifest.setPolicyFiles(List.of(FileReferenceDTO.builder().path(recipe.toString()).sha256(
                HexFormat.of().formatHex(MessageDigest.getInstance("SHA-256").digest(Files.readAllBytes(recipe)))).build()));
        Path manifestFile = preparedIntent(manifest);
        Path rbacReceipt = root.resolve("evidence/db-rbac.json");
        privateJson(rbacReceipt, receiptFor(manifest, manifestFile));
        var inputs = readVerifiedDatabaseInputs(manifestFile, rbacReceipt, temporaryRepository, "rbac");
        var tianshuReceipt = receiptFor(manifest, manifestFile).setRole("tianshu")
                .setDatabaseName(DATABASE_NAMES.get("tianshu")).setOid(43);
        privateJson(root.resolve("evidence/db-tianshu.json"), tianshuReceipt);
        Path registry = root.resolve("secrets/runtime-registry.json");
        privateJson(registry, Map.of("schemaVersion", 1, "runId", manifest.getRunId(), "manifestSha256", inputs.getManifestSha256(),
                "tenantIds", Map.of("default", "1001", "tenant-b", "1002"), "subjects", Map.of("admin", "controlled-actual-admin", "viewer", "controlled-actual-viewer")));
        String marker = "xingyuan-it:" + manifest.getRunId() + ":platform-catalog";
        Map<String, Object> businesses = new LinkedHashMap<>();
        Map<String, Object> applications = new LinkedHashMap<>();
        for (int i = 0; i < 3; i++) {
            String code = businessCodes.get(i);
            businesses.put(code, Map.of("id", Long.toString(6001L + i), "bizCode", code, "bizName", code,
                    "description", marker, "enabled", true, "createdAt", "2026-10-14T00:00:00", "updatedAt", "2026-10-14T00:00:00"));
        }
        for (int i = 0; i < 4; i++) {
            applications.put(appCodes.get(i), Map.of("id", Long.toString(7001L + i), "appCode", appCodes.get(i), "bizCode", bizCodes.get(i),
                    "appName", appCodes.get(i), "owner", "controlled-actual-admin", "description", marker, "enabled", true,
                    "createdAt", "2026-10-14T00:00:00", "updatedAt", "2026-10-14T00:00:00"));
        }
        Map<String, Object> catalog = new LinkedHashMap<>();
        catalog.put("schemaVersion", 1); catalog.put("runId", manifest.getRunId()); catalog.put("manifestSha256", inputs.getManifestSha256());
        catalog.put("databaseOid", 43); catalog.put("recipeSha256", manifest.getPolicyFiles().getFirst().getSha256());
        catalog.put("registrySha256", HexFormat.of().formatHex(MessageDigest.getInstance("SHA-256").digest(Files.readAllBytes(registry))));
        catalog.put("tenantId", "1001"); catalog.put("status", "COMMITTED"); catalog.put("recordedAt", "2026-10-14T00:00:00Z");
        catalog.put("businesses", businesses); catalog.put("applications", applications);
        privateJson(root.resolve("evidence/tianshu-platform-catalog.json"), catalog);
        Map<String, Object> control = new LinkedHashMap<>();
        control.put("schemaVersion", 1); control.put("operationId", "CLI-003"); control.put("runId", manifest.getRunId());
        control.put("manifestSha256", inputs.getManifestSha256()); control.put("status", "RUNNING"); control.put("completedAt", "2026-10-14T00:00:00Z");
        control.put("targets", List.of(Map.of("targetKey", "controlled-process", "identity", "1234", "version", "2026-10-14T00:00:00Z", "state", "RUNNING")));
        control.put("counts", Map.of("databaseCount", 9, "tenantCount", 2, "clientCount", 0, "catalogCount", 4, "liveCaseCount", 0));
        control.put("steps", List.of(Map.of("stepId", "CONTROL_PLANE", "state", "RUNNING", "evidence", "evidence/control-plane.json")));
        control.put("error", null);
        privateJson(root.resolve("evidence/control-plane.json"), control);
        return inputs;
    }

    static Map<String, Object> readOwnerProperties(VerifiedDatabaseInputsBO inputs) throws IOException {
        Path root = Path.of(inputs.getManifest().getRuntimeRoot());
        Path file = root.resolve("profiles/jianshen.properties");
        requirePrivateDirectory(root.resolve("profiles"));
        var receipt = strictMapper().readTree(readProtectedBytes(root.resolve("evidence/profiles-ready.json"), root.resolve("evidence"), 128 * 1024));
        if (!inputs.getManifest().getRunId().equals(receipt.path("runId").asText())
                || !inputs.getManifestSha256().equals(receipt.path("manifestSha256").asText())
                || !file.toString().equals(receipt.path("profiles").path("jianshen").path("path").asText())) {
            throw new IllegalArgumentException("XINGYUAN_TARGET_UNSAFE");
        }
        byte[] bytes = readProtectedBytes(file, root.resolve("profiles"), 128 * 1024);
        try {
            if (!HexFormat.of().formatHex(MessageDigest.getInstance("SHA-256").digest(bytes))
                    .equals(receipt.path("profiles").path("jianshen").path("sha256").asText())) {
                throw new IllegalArgumentException("XINGYUAN_TARGET_UNSAFE");
            }
            var properties = new java.util.Properties();
            properties.load(new java.io.StringReader(new String(bytes, StandardCharsets.UTF_8)));
            if (!inputs.getManifest().getRunId().equals(properties.getProperty("xingyuan.isolated.run-id"))) {
                throw new IllegalArgumentException("XINGYUAN_TARGET_UNSAFE");
            }
            Map<String, Object> result = new LinkedHashMap<>();
            for (String key : properties.stringPropertyNames()) {
                result.put(key, properties.getProperty(key));
            }
            var registry = strictMapper().readTree(readProtectedBytes(root.resolve("secrets/runtime-registry.json"), root.resolve("secrets"), 2 * 1024 * 1024));
            if (!inputs.getManifest().getRunId().equals(registry.path("runId").asText())
                    || !inputs.getManifestSha256().equals(registry.path("manifestSha256").asText())) {
                throw new IllegalArgumentException("XINGYUAN_TARGET_UNSAFE");
            }
            Set<String> issuers = new HashSet<>();
            issuers.add(inputs.getManifest().getPublicOrigin() + "/platform");
            for (String code : inputs.getManifest().getTenantCodes()) {
                String tenant = registry.path("tenantIds").path(code).asText();
                if (!tenant.matches("[1-9][0-9]{0,18}")) {
                    throw new IllegalArgumentException("XINGYUAN_TARGET_UNSAFE");
                }
                issuers.add(inputs.getManifest().getPublicOrigin() + "/tenants/" + tenant);
            }
            for (var entry : result.entrySet()) {
                String key = entry.getKey();
                String suffix = key.endsWith(".token-uri") ? "/oauth2/token"
                        : key.endsWith(".authorization-uri") ? "/oauth2/authorize"
                        : key.endsWith(".jwk-set-uri") || key.endsWith(".jwks-uri") ? "/.well-known/jwks.json"
                        : key.endsWith(".user-info-uri") ? "/userinfo"
                        : key.endsWith(".issuer-uri") || key.endsWith(".issuer") || key.endsWith(".fallback-issuer") ? "" : null;
                if (suffix != null && issuers.stream().noneMatch(issuer -> (issuer + suffix).equals(entry.getValue()))) {
                    throw new IllegalArgumentException("XINGYUAN_TARGET_UNSAFE");
                }
            }
            return Map.copyOf(result);
        } catch (NoSuchAlgorithmException unavailable) {
            throw new IllegalStateException("XINGYUAN_INPUT_UNAVAILABLE");
        } finally {
            Arrays.fill(bytes, (byte) 0);
        }
    }

    static void installTaskTls(AnnotationConfigApplicationContext context, VerifiedDatabaseInputsBO inputs) throws IOException {
        String reference = inputs.getManifest().getSecretFiles().get("tls-ca-cert");
        if (reference == null) {
            throw new IllegalArgumentException("XINGYUAN_INPUT_UNAVAILABLE");
        }
        try {
            byte[] certificate = readProtectedBytes(Path.of(reference), Path.of(inputs.getManifest().getRuntimeRoot()).resolve("secrets"), 128 * 1024);
            var ca = (java.security.cert.X509Certificate) java.security.cert.CertificateFactory.getInstance("X.509")
                    .generateCertificate(new java.io.ByteArrayInputStream(certificate));
            ca.checkValidity();
            ca.verify(ca.getPublicKey());
            if (ca.getBasicConstraints() < 0) {
                throw new IllegalArgumentException("XINGYUAN_TARGET_UNSAFE");
            }
            var store = java.security.KeyStore.getInstance("PKCS12");
            store.load(null, null);
            store.setCertificateEntry("xingyuan-task-ca", ca);
            var managers = javax.net.ssl.TrustManagerFactory.getInstance(javax.net.ssl.TrustManagerFactory.getDefaultAlgorithm());
            managers.init(store);
            var task = javax.net.ssl.SSLContext.getInstance("TLS");
            task.init(null, managers.getTrustManagers(), new java.security.SecureRandom());
            var previous = javax.net.ssl.SSLContext.getDefault();
            var previousFactory = javax.net.ssl.HttpsURLConnection.getDefaultSSLSocketFactory();
            context.getDefaultListableBeanFactory().registerDisposableBean("isolatedTaskTls", () -> {
                javax.net.ssl.SSLContext.setDefault(previous);
                javax.net.ssl.HttpsURLConnection.setDefaultSSLSocketFactory(previousFactory);
            });
            javax.net.ssl.SSLContext.setDefault(task);
            javax.net.ssl.HttpsURLConnection.setDefaultSSLSocketFactory(task.getSocketFactory());
        } catch (java.security.GeneralSecurityException rejected) {
            throw new IllegalArgumentException("XINGYUAN_TARGET_UNSAFE");
        }
    }

    static RedissonClient ownedRegistryRedis(VerifiedDatabaseInputsBO inputs) throws IOException {
        char[] password = readProtectedCharacters(Path.of(inputs.getManifest().getRedis().getCredentialFile()), null, 4096);
        try {
            if (password.length == 0) {
                throw new IllegalArgumentException("XINGYUAN_INPUT_INVALID");
            }
            var config = new org.redisson.config.Config().setThreads(2).setNettyThreads(2)
                    .setCodec(new org.redisson.codec.JsonJacksonCodec(strictMapper()));
            config.useSingleServer().setAddress(inputs.getManifest().getRedis().getEndpoint())
                    .setDatabase(inputs.getManifest().getRedis().getDatabase()).setPassword(new String(password))
                    .setClientName("xingyuan-it:" + inputs.getManifest().getRunId() + ":registry-client")
                    .setConnectTimeout(1000).setTimeout(500).setRetryAttempts(0)
                    .setConnectionMinimumIdleSize(1).setConnectionPoolSize(2)
                    .setSubscriptionConnectionMinimumIdleSize(1).setSubscriptionConnectionPoolSize(2);
            var redis = org.redisson.Redisson.create(config);
            try {
                verifyRegistryRedisOwnership(redis, inputs);
                return redis;
            } catch (RuntimeException rejected) {
                redis.shutdown();
                throw rejected;
            }
        } finally {
            Arrays.fill(password, '\0');
        }
    }

    static void verifyRegistryRedisOwnership(RedissonClient redis, VerifiedDatabaseInputsBO inputs) {
        var config = redis.getConfig();
        if (config == null || config.isClusterConfig() || config.isSentinelConfig()) {
            throw new IllegalArgumentException("XINGYUAN_TARGET_UNSAFE");
        }
        var single = config.useSingleServer();
        if (!inputs.getManifest().getRedis().getEndpoint().equals(single.getAddress())
                || inputs.getManifest().getRedis().getDatabase() != single.getDatabase()) {
            throw new IllegalArgumentException("XINGYUAN_TARGET_UNSAFE");
        }
        String expected = "xingyuan-it:" + inputs.getManifest().getRunId() + ":" + inputs.getManifestSha256();
        if (!expected.equals(redis.<String>getBucket("xingyuan-it:owner", StringCodec.INSTANCE).get())) {
            throw new IllegalArgumentException("XINGYUAN_TARGET_UNSAFE");
        }
    }





    @Test
    void ownerProfilesBindTheRunRegistryHashAndExactLocalIssuerBeforeContextCreation() throws Exception {
        var manifest = intent();
        Path input = preparedIntent(manifest);
        Path root = Path.of(manifest.getRuntimeRoot());
        Path receiptFile = root.resolve("evidence/db-rbac.json");
        privateJson(receiptFile, receiptFor(manifest, input));
        var inputs = readVerifiedDatabaseInputs(input, receiptFile, temporaryRepository, "rbac");
        Files.createDirectory(root.resolve("profiles"));
        Files.createDirectory(root.resolve("secrets"));
        privateDirectory(root.resolve("profiles"));
        privateDirectory(root.resolve("secrets"));
        privateJson(root.resolve("secrets/runtime-registry.json"), Map.of("runId", manifest.getRunId(),
                "manifestSha256", inputs.getManifestSha256(), "tenantIds", Map.of("default", "1001", "tenant-b", "1002")));
        Path profile = root.resolve("profiles/jianshen.properties");
        String content = "xingyuan.isolated.run-id=" + manifest.getRunId() + "\n"
                + "spring.security.oauth2.client.provider.task.issuer-uri=https://127.0.0.1:28443/tenants/1001\n"
                + "spring.security.oauth2.client.provider.task.token-uri=https://127.0.0.1:28443/tenants/1001/oauth2/token\n"
                + "spring.security.oauth2.client.provider.task.jwk-set-uri=https://127.0.0.1:28443/tenants/1001/.well-known/jwks.json\n"
                + "egon.cola.platform.tianquan.shoubing.trusted-issuers.task.jwks-uri=https://127.0.0.1:28443/tenants/1001/.well-known/jwks.json\n"
                + "controlled.value=\\ leading\\ space\\nline\n";
        Files.writeString(profile, content);
        Files.setPosixFilePermissions(profile, PosixFilePermissions.fromString("rw-------"));
        writeProfileReceipt(inputs, profile);
        assertThat(readOwnerProperties(inputs)).containsEntry("controlled.value", " leading space\nline");
        Files.writeString(profile, content.replace("/.well-known/jwks.json", "/oauth2/jwks"));
        writeProfileReceipt(inputs, profile);
        assertThatThrownBy(() -> readOwnerProperties(inputs)).hasMessage("XINGYUAN_TARGET_UNSAFE");
        Files.writeString(profile, content);
        writeProfileReceipt(inputs, profile);
        Files.writeString(profile, content.replace("https://127.0.0.1:28443/tenants/1001/oauth2/token", "https://foreign.example/oauth2/token"));
        assertThatThrownBy(() -> readOwnerProperties(inputs)).hasMessage("XINGYUAN_TARGET_UNSAFE");
        writeProfileReceipt(inputs, profile);
        assertThatThrownBy(() -> readOwnerProperties(inputs)).hasMessage("XINGYUAN_TARGET_UNSAFE");
    }

    private static void writeProfileReceipt(VerifiedDatabaseInputsBO inputs, Path profile) throws Exception {
        String checksum = HexFormat.of().formatHex(MessageDigest.getInstance("SHA-256").digest(Files.readAllBytes(profile)));
        Path receipt = Path.of(inputs.getManifest().getRuntimeRoot()).resolve("evidence/profiles-ready.json");
        Files.deleteIfExists(receipt);
        privateJson(receipt, Map.of("schemaVersion", 1, "runId", inputs.getManifest().getRunId(),
                "manifestSha256", inputs.getManifestSha256(), "profiles", Map.of("jianshen", Map.of("path", profile.toString(), "sha256", checksum))));
    }

    @Test
    void anUnmatchedRegistryRedisOwnerCannotReachTheBusinessServiceRegistry() {
        var manifest = intent();
        var inputs = VerifiedDatabaseInputsBO.builder().manifest(manifest).manifestSha256("a".repeat(64)).build();
        var redis = org.mockito.Mockito.mock(RedissonClient.class);
        var config = new org.redisson.config.Config();
        config.useSingleServer().setAddress(manifest.getRedis().getEndpoint()).setDatabase(manifest.getRedis().getDatabase());
        org.mockito.Mockito.when(redis.getConfig()).thenReturn(config);
        @SuppressWarnings("unchecked")
        org.redisson.api.RBucket<String> marker = org.mockito.Mockito.mock(org.redisson.api.RBucket.class);
        org.mockito.Mockito.when(redis.<String>getBucket("xingyuan-it:owner", StringCodec.INSTANCE)).thenReturn(marker);
        org.mockito.Mockito.when(marker.get()).thenReturn("foreign-owner");
        assertThatThrownBy(() -> verifyRegistryRedisOwnership(redis, inputs)).hasMessage("XINGYUAN_TARGET_UNSAFE");
        org.mockito.Mockito.when(marker.get()).thenReturn("xingyuan-it:" + manifest.getRunId() + ":" + inputs.getManifestSha256());
        verifyRegistryRedisOwnership(redis, inputs);
        org.mockito.Mockito.clearInvocations(marker);
        config.useSingleServer().setDatabase(0);
        assertThatThrownBy(() -> verifyRegistryRedisOwnership(redis, inputs)).hasMessage("XINGYUAN_TARGET_UNSAFE");
        org.mockito.Mockito.verifyNoInteractions(marker);
    }



    @Test
    void rejectedPhysicalConnectionIsClosedAndCannotReachAnOwner() throws Exception {
        var physical = org.mockito.Mockito.mock(DataSource.class);
        var connection = org.mockito.Mockito.mock(Connection.class);
        var query = org.mockito.Mockito.mock(java.sql.PreparedStatement.class);
        var rows = org.mockito.Mockito.mock(java.sql.ResultSet.class);
        org.mockito.Mockito.when(physical.getConnection()).thenReturn(connection);
        org.mockito.Mockito.when(connection.prepareStatement(org.mockito.ArgumentMatchers.anyString())).thenReturn(query);
        org.mockito.Mockito.when(query.executeQuery()).thenReturn(rows);
        org.mockito.Mockito.when(rows.next()).thenReturn(true, false);
        org.mockito.Mockito.when(rows.getString(1)).thenReturn("foreign-database");
        var receipt = IsolatedDatabaseReceiptDTO.builder().databaseName(DATABASE_NAMES.get("rbac"))
                .oid(42L).databaseOwner("controlled-owner").ownerComment("owned-task").build();
        assertThatThrownBy(() -> guardPhysicalDataSource(physical, receipt).getConnection())
                .hasMessage("XINGYUAN_TARGET_UNSAFE");
        org.mockito.Mockito.verify(connection).close();
        org.mockito.Mockito.verify(query).setQueryTimeout(5);
        org.mockito.Mockito.verify(query).close();
        org.mockito.Mockito.verify(rows).close();
    }

    @Test
    void anOwnedDatabaseConnectionMustMatchEveryReceiptAndEndpointFact() throws Exception {
        var physical = org.mockito.Mockito.mock(DataSource.class);
        var connection = org.mockito.Mockito.mock(Connection.class);
        var query = org.mockito.Mockito.mock(java.sql.PreparedStatement.class);
        var rows = org.mockito.Mockito.mock(java.sql.ResultSet.class);
        org.mockito.Mockito.when(physical.getConnection()).thenReturn(connection);
        org.mockito.Mockito.when(connection.prepareStatement(org.mockito.ArgumentMatchers.anyString())).thenReturn(query);
        org.mockito.Mockito.when(query.executeQuery()).thenReturn(rows);
        var receipt = IsolatedDatabaseReceiptDTO.builder().databaseName(DATABASE_NAMES.get("rbac"))
                .oid(42L).databaseOwner("controlled-owner").ownerComment("owned-task").build();
        org.mockito.Mockito.when(rows.getString(1)).thenReturn(receipt.getDatabaseName());
        org.mockito.Mockito.when(rows.getString(2)).thenReturn("127.0.0.1");
        org.mockito.Mockito.when(rows.getInt(3)).thenReturn(5432);
        org.mockito.Mockito.when(rows.getLong(4)).thenReturn(42L);
        org.mockito.Mockito.when(rows.getString(5)).thenReturn(receipt.getOwnerComment());
        org.mockito.Mockito.when(rows.getString(6)).thenReturn(receipt.getDatabaseOwner());
        var guarded = guardPhysicalDataSource(physical, receipt);
        for (String fault : List.of("OID", "ADDRESS", "PORT", "COMMENT", "OWNER", "MULTIPLE")) {
            org.mockito.Mockito.when(rows.next()).thenReturn(true, false);
            switch (fault) {
                case "OID" -> org.mockito.Mockito.when(rows.getLong(4)).thenReturn(43L);
                case "ADDRESS" -> org.mockito.Mockito.when(rows.getString(2)).thenReturn("192.0.2.1");
                case "PORT" -> org.mockito.Mockito.when(rows.getInt(3)).thenReturn(5433);
                case "COMMENT" -> org.mockito.Mockito.when(rows.getString(5)).thenReturn("foreign-owner");
                case "OWNER" -> org.mockito.Mockito.when(rows.getString(6)).thenReturn("foreign-user");
                case "MULTIPLE" -> org.mockito.Mockito.when(rows.next()).thenReturn(true, true);
                default -> throw new AssertionError(fault);
            }
            assertThatThrownBy(guarded::getConnection).as(fault).hasMessage("XINGYUAN_TARGET_UNSAFE");
            org.mockito.Mockito.when(rows.getLong(4)).thenReturn(42L);
            org.mockito.Mockito.when(rows.getString(2)).thenReturn("127.0.0.1");
            org.mockito.Mockito.when(rows.getInt(3)).thenReturn(5432);
            org.mockito.Mockito.when(rows.getString(5)).thenReturn(receipt.getOwnerComment());
            org.mockito.Mockito.when(rows.getString(6)).thenReturn(receipt.getDatabaseOwner());
        }
        org.mockito.Mockito.when(rows.next()).thenReturn(true, false);
        assertThat(guarded.getConnection()).isSameAs(connection);
        org.mockito.Mockito.verify(connection, org.mockito.Mockito.times(6)).close();
        assertThatThrownBy(() -> guarded.getConnection("other-user", "controlled-value"))
                .hasMessage("XINGYUAN_TARGET_UNSAFE");
        org.mockito.Mockito.verify(physical, org.mockito.Mockito.never())
                .getConnection(org.mockito.ArgumentMatchers.anyString(), org.mockito.ArgumentMatchers.anyString());
    }

    /** The PG transaction cases consume a dedicated role prepared through real owners, never an application admin role. */
    public static AuthorizationTransactionProbeDTO readTransactionProbe(VerifiedDatabaseInputsBO inputs) throws IOException {
        Path root = Path.of(inputs.getManifest().getRuntimeRoot());
        Path file = root.resolve("policies/transaction-probe.json");
        var references = inputs.getManifest().getPolicyFiles().stream()
                .filter(reference -> file.toString().equals(reference.getPath())).toList();
        if (references.size() != 1) {
            throw new IllegalArgumentException("XINGYUAN_INPUT_UNAVAILABLE");
        }
        byte[] bytes = readProtectedBytes(file, root, 2 * 1024 * 1024);
        String digest;
        try {
            digest = HexFormat.of().formatHex(MessageDigest.getInstance("SHA-256").digest(bytes));
        } catch (NoSuchAlgorithmException unavailableAlgorithm) {
            throw new IllegalStateException("XINGYUAN_INPUT_UNAVAILABLE");
        }
        if (!digest.equals(references.getFirst().getSha256())) {
            throw new IllegalArgumentException("XINGYUAN_TARGET_UNSAFE");
        }
        var probe = strictMapper().readValue(bytes, AuthorizationTransactionProbeDTO.class);
        try (var validators = Validation.buildDefaultValidatorFactory()) {
            if (!validators.getValidator().validate(probe).isEmpty()) {
                throw new IllegalArgumentException("XINGYUAN_INPUT_INVALID");
            }
        }
        var registry = strictMapper().readTree(readProtectedBytes(root.resolve("secrets/runtime-registry.json"), root.resolve("secrets"), 2 * 1024 * 1024));
        if (!inputs.getManifest().getRunId().equals(probe.getRunId())
                || !inputs.getManifest().getRunId().equals(registry.path("runId").asText())
                || !inputs.getManifestSha256().equals(registry.path("manifestSha256").asText())
                || !probe.getTenantId().equals(registry.path("tenantIds").path("default").asText())
                || !probe.getActorId().equals(registry.path("subjects").path("admin").asText())) {
            throw new IllegalArgumentException("XINGYUAN_TARGET_UNSAFE");
        }
        return probe;
    }

    public static VerifiedDatabaseInputsBO readTransactionInputs() throws IOException {
        if (!"true".equals(System.getenv("XINGYUAN_ISOLATED_INTEGRATION"))) {
            throw new IllegalArgumentException("XINGYUAN_TARGET_UNSAFE");
        }
        String reference = System.getenv("XINGYUAN_INTEGRATION_MANIFEST");
        String repository = System.getProperty("xingyuan.isolated.repository-root");
        if (reference == null || reference.isBlank() || repository == null || repository.isBlank()) {
            throw new IllegalArgumentException("XINGYUAN_INPUT_UNAVAILABLE");
        }
        Path manifest = Path.of(reference);
        return readVerifiedDatabaseInputs(manifest, manifest.getParent().resolve("evidence/db-rbac.json"), Path.of(repository), "rbac");
    }

    @Data
    @NoArgsConstructor
    @AllArgsConstructor
    @Accessors(chain = true)
    @Builder
    public static class AuthorizationTransactionProbeDTO {
        @Min(1) @Max(1) private int schemaVersion;
        @NotBlank @Pattern(regexp = "[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}") private String runId;
        @NotBlank @Pattern(regexp = "[1-9][0-9]{0,18}") private String tenantId;
        @NotBlank @Pattern(regexp = "[1-9][0-9]{0,18}") private String roleId;
        @NotBlank @Size(max = 200) private String actorId;
    }

    static VerifiedDatabaseInputsBO guardedInputs(Path manifest, Path receipt, Path repository,
                                                  Runnable writer) throws IOException {
        var inputs = readVerifiedDatabaseInputs(manifest, receipt, repository, "rbac");
        writer.run();
        return inputs;
    }

    @Test
    void mismatchedReceiptNeverReachesAnAuthorizationOwner() throws Exception {
        var manifest = intent();
        Path root = Path.of(manifest.getRuntimeRoot());
        Files.createDirectories(root.resolve("evidence"));
        privateDirectory(root);
        privateDirectory(root.resolve("evidence"));
        Path input = root.resolve("intent.json");
        Path receipt = root.resolve("evidence/db-rbac.json");
        privateJson(input, manifest);
        privateJson(receipt, IsolatedDatabaseReceiptDTO.builder().runId(manifest.getRunId())
                .manifestSha256("0".repeat(64)).role("rbac").databaseName(DATABASE_NAMES.get("rbac"))
                .oid(42).databaseOwner("controlled-owner").ownerComment("foreign-owner").build());
        var writes = new AtomicInteger();
        assertThatThrownBy(() -> guardedInputs(input, receipt, temporaryRepository, writes::incrementAndGet))
                .isInstanceOf(IllegalArgumentException.class).hasMessage("XINGYUAN_TARGET_UNSAFE");
        assertThat(writes).hasValue(0);
    }

    static void requirePrivateDirectory(Path directory) throws IOException {
        for (Path current = directory; current != null; current = current.getParent()) {
            if (Files.isSymbolicLink(current)) {
                throw new IllegalArgumentException("XINGYUAN_TARGET_UNSAFE");
            }
        }
        var user = directory.getFileSystem().getUserPrincipalLookupService()
                .lookupPrincipalByName(System.getProperty("user.name"));
        if (!Files.isDirectory(directory, LinkOption.NOFOLLOW_LINKS)
                || !Files.getOwner(directory, LinkOption.NOFOLLOW_LINKS).equals(user)
                || !Files.getPosixFilePermissions(directory, LinkOption.NOFOLLOW_LINKS)
                .equals(PosixFilePermissions.fromString("rwx------"))) {
            throw new IllegalArgumentException("XINGYUAN_TARGET_UNSAFE");
        }
    }

    private static void privateDirectory(Path path) throws IOException {
        Files.setPosixFilePermissions(path, PosixFilePermissions.fromString("rwx------"));
    }

    @Test
    void validOwnershipBindsOnlyThePreparedRbacDatabase() throws Exception {
        var manifest = intent();
        Path input = preparedIntent(manifest);
        Path receipt = Path.of(manifest.getRuntimeRoot()).resolve("evidence/db-rbac.json");
        privateJson(receipt, receiptFor(manifest, input));
        var writes = new AtomicInteger();
        var inputs = guardedInputs(input, receipt, temporaryRepository, writes::incrementAndGet);
        assertThat(inputs.getJdbcUrl()).isEqualTo("jdbc:postgresql://127.0.0.1:5432/xingyuan_it_rbac_20261011");
        assertThat(writes).hasValue(1);
    }

    @Test
    void replacedRunDigestRoleOidAndCommentNeverReachAnOwner() throws Exception {
        var manifest = intent();
        Path input = preparedIntent(manifest);
        Path file = Path.of(manifest.getRuntimeRoot()).resolve("evidence/db-rbac.json");
        var writes = new AtomicInteger();
        for (String fault : List.of("RUN", "HASH", "ROLE", "DATABASE", "OID", "OWNER", "COMMENT")) {
            var receipt = receiptFor(manifest, input);
            switch (fault) {
                case "RUN" -> receipt.setRunId(UUID.randomUUID().toString());
                case "HASH" -> receipt.setManifestSha256("0".repeat(64));
                case "ROLE" -> receipt.setRole("idp");
                case "DATABASE" -> receipt.setDatabaseName("egon_cola");
                case "OID" -> receipt.setOid(0L);
                case "OWNER" -> receipt.setDatabaseOwner(" ");
                case "COMMENT" -> receipt.setOwnerComment("foreign-owner");
                default -> throw new AssertionError(fault);
            }
            Files.deleteIfExists(file);
            privateJson(file, receipt);
            assertThatThrownBy(() -> guardedInputs(input, file, temporaryRepository, writes::incrementAndGet))
                    .as(fault).hasMessage("XINGYUAN_TARGET_UNSAFE");
        }
        assertThat(writes).hasValue(0);
    }

    @Test
    void missingExternalSymlinkAndPublicReceiptsNeverReachAnOwner() throws Exception {
        var manifest = intent();
        Path input = preparedIntent(manifest);
        Path root = Path.of(manifest.getRuntimeRoot());
        var writes = new AtomicInteger();
        Path missing = root.resolve("evidence/missing.json");
        assertThatThrownBy(() -> guardedInputs(input, missing, temporaryRepository, writes::incrementAndGet))
                .hasMessage("XINGYUAN_INPUT_UNAVAILABLE");
        Path external = temporaryRepository.resolve("foreign-receipt.json");
        privateJson(external, receiptFor(manifest, input));
        assertThatThrownBy(() -> guardedInputs(input, external, temporaryRepository, writes::incrementAndGet))
                .hasMessage("XINGYUAN_TARGET_UNSAFE");
        Path link = root.resolve("evidence/link.json");
        Files.createSymbolicLink(link, external);
        assertThatThrownBy(() -> guardedInputs(input, link, temporaryRepository, writes::incrementAndGet))
                .hasMessage("XINGYUAN_TARGET_UNSAFE");
        Path file = root.resolve("evidence/public.json");
        privateJson(file, receiptFor(manifest, input));
        Files.setPosixFilePermissions(file, PosixFilePermissions.fromString("rw-r--r--"));
        assertThatThrownBy(() -> guardedInputs(input, file, temporaryRepository, writes::incrementAndGet))
                .hasMessage("XINGYUAN_TARGET_UNSAFE");
        assertThat(writes).hasValue(0);
    }

    @Test
    void aSharedTaskDirectoryCannotAuthorizeALiveContext() throws Exception {
        var manifest = intent();
        Path input = preparedIntent(manifest);
        Path root = Path.of(manifest.getRuntimeRoot());
        Path receipt = root.resolve("evidence/db-rbac.json");
        privateJson(receipt, receiptFor(manifest, input));
        Files.setPosixFilePermissions(root, PosixFilePermissions.fromString("rwxr-xr-x"));
        var writes = new AtomicInteger();
        assertThatThrownBy(() -> guardedInputs(input, receipt, temporaryRepository, writes::incrementAndGet))
                .hasMessage("XINGYUAN_TARGET_UNSAFE");
        assertThat(writes).hasValue(0);
    }

    @Test
    void malformedOrCoercedTransportCannotReachAnOwner() throws Exception {
        var manifest = intent();
        Path input = preparedIntent(manifest);
        String json = strictMapper().writeValueAsString(manifest);
        var writes = new AtomicInteger();
        for (String content : List.of(json + " {}", json.replace("\"schemaVersion\":1", "\"schemaVersion\":true"),
                json.replace("\"schemaVersion\":1", "\"schemaVersion\":1,\"schemaVersion\":1"),
                json.substring(0, json.length() - 1) + ",\"rawToken\":\"private-input\"}")) {
            Files.writeString(input, content);
            assertThatThrownBy(() -> guardedInputs(input, input, temporaryRepository, writes::incrementAndGet))
                    .isInstanceOf(IOException.class);
        }
        assertThat(writes).hasValue(0);
    }

    private Path preparedIntent(IsolatedIntegrationManifestDTO manifest) throws IOException {
        Path root = Path.of(manifest.getRuntimeRoot());
        Files.createDirectories(root.resolve("evidence"));
        privateDirectory(root);
        privateDirectory(root.resolve("evidence"));
        Path input = root.resolve("intent.json");
        privateJson(input, manifest);
        return input;
    }

    private static IsolatedDatabaseReceiptDTO receiptFor(IsolatedIntegrationManifestDTO manifest,
                                                         Path input) throws Exception {
        String digest = HexFormat.of().formatHex(MessageDigest.getInstance("SHA-256").digest(Files.readAllBytes(input)));
        return IsolatedDatabaseReceiptDTO.builder().runId(manifest.getRunId()).manifestSha256(digest)
                .role("rbac").databaseName(DATABASE_NAMES.get("rbac")).oid(42L).databaseOwner("controlled-owner")
                .ownerComment("xingyuan-it:" + manifest.getRunId() + ":" + digest).build();
    }

    private static void privateJson(Path path, Object value) throws IOException {
        Files.write(path, strictMapper().writeValueAsBytes(value), StandardOpenOption.CREATE_NEW);
        Files.setPosixFilePermissions(path, PosixFilePermissions.fromString("rw-------"));
    }

    @Test
    void aTaskFileInAPublicDirectoryIsRejectedEvenWhenTheFileIsPrivate() throws Exception {
        Path task = temporaryRepository.resolve("private-task");
        Files.createDirectory(task, PosixFilePermissions.asFileAttribute(PosixFilePermissions.fromString("rwx------")));
        Path exposed = Files.createDirectory(task.resolve("exposed"), PosixFilePermissions.asFileAttribute(PosixFilePermissions.fromString("rwxr-xr-x")));
        Path file = exposed.resolve("recipe.json");
        Files.writeString(file, "{}");
        Files.setPosixFilePermissions(file, PosixFilePermissions.fromString("rw-------"));
        org.junit.jupiter.api.Assertions.assertThrows(IllegalArgumentException.class, () -> readProtectedBytes(file, task, 100));
    }

    static byte[] readProtectedBytes(Path file, Path taskRoot, int maximumBytes) throws IOException {
        if (!file.isAbsolute() || !file.equals(file.normalize()) || maximumBytes < 1) {
            throw new IllegalArgumentException("XINGYUAN_TARGET_UNSAFE");
        }
        if (taskRoot != null && (!taskRoot.isAbsolute() || !taskRoot.equals(taskRoot.normalize())
                || file.equals(taskRoot) || !file.startsWith(taskRoot))) {
            throw new IllegalArgumentException("XINGYUAN_TARGET_UNSAFE");
        }
        for (Path current = file; current != null; current = current.getParent()) {
            if (Files.isSymbolicLink(current)) {
                throw new IllegalArgumentException("XINGYUAN_TARGET_UNSAFE");
            }
        }
        if (!Files.isRegularFile(file, LinkOption.NOFOLLOW_LINKS)) {
            throw new IllegalArgumentException("XINGYUAN_INPUT_UNAVAILABLE");
        }
        var user = file.getFileSystem().getUserPrincipalLookupService()
                .lookupPrincipalByName(System.getProperty("user.name"));
        if (taskRoot != null) {
            for (Path directory = file.getParent(); directory != null && directory.startsWith(taskRoot); directory = directory.getParent()) {
                if (!Files.isDirectory(directory, LinkOption.NOFOLLOW_LINKS)
                        || !Files.getOwner(directory, LinkOption.NOFOLLOW_LINKS).equals(user)
                        || !Files.getPosixFilePermissions(directory, LinkOption.NOFOLLOW_LINKS)
                        .equals(PosixFilePermissions.fromString("rwx------"))) {
                    throw new IllegalArgumentException("XINGYUAN_TARGET_UNSAFE");
                }
            }
        }
        if (!Files.getOwner(file, LinkOption.NOFOLLOW_LINKS).equals(user)
                || !Files.getPosixFilePermissions(file, LinkOption.NOFOLLOW_LINKS)
                .equals(PosixFilePermissions.fromString("rw-------"))) {
            throw new IllegalArgumentException("XINGYUAN_TARGET_UNSAFE");
        }
        BasicFileAttributes before = Files.readAttributes(file, BasicFileAttributes.class,
                LinkOption.NOFOLLOW_LINKS);
        if (before.size() > maximumBytes) {
            throw new IllegalArgumentException("XINGYUAN_INPUT_INVALID");
        }
        byte[] contents;
        try (var input = Files.newInputStream(file, StandardOpenOption.READ, LinkOption.NOFOLLOW_LINKS)) {
            contents = input.readNBytes(maximumBytes + 1);
        }
        BasicFileAttributes after = Files.readAttributes(file, BasicFileAttributes.class,
                LinkOption.NOFOLLOW_LINKS);
        if (contents.length > maximumBytes) {
            throw new IllegalArgumentException("XINGYUAN_INPUT_INVALID");
        }
        if (!Objects.equals(before.fileKey(), after.fileKey())
                || before.size() != after.size()
                || !before.lastModifiedTime().equals(after.lastModifiedTime())) {
            throw new IllegalArgumentException("XINGYUAN_TARGET_UNSAFE");
        }
        return contents;
    }

    static void validateDatabaseReceipt(IsolatedIntegrationManifestDTO manifest, String digest,
                                        String role, IsolatedDatabaseReceiptDTO receipt) {
        validateTargets(manifest, Path.of(manifest.getRepoRoot()));
        if (receipt == null || digest == null || !digest.matches("[0-9a-f]{64}")
                || !manifest.getRunId().equals(receipt.getRunId())
                || !digest.equals(receipt.getManifestSha256())
                || !role.equals(receipt.getRole())
                || !Objects.equals(DATABASE_NAMES.get(role), receipt.getDatabaseName())
                || receipt.getOid() <= 0L
                || receipt.getDatabaseOwner() == null || receipt.getDatabaseOwner().isBlank()
                || !("xingyuan-it:" + manifest.getRunId() + ":" + digest).equals(receipt.getOwnerComment())) {
            throw new IllegalArgumentException("XINGYUAN_TARGET_UNSAFE");
        }
    }

    static VerifiedDatabaseInputsBO readVerifiedDatabaseInputs(
            Path manifestFile, Path receiptFile, Path repository, String role) throws IOException {
        byte[] manifestBytes = readProtectedBytes(manifestFile, null, 128 * 1024);
        var manifest = strictMapper().readValue(manifestBytes, IsolatedIntegrationManifestDTO.class);
        validateTargets(manifest, repository);
        Path taskRoot = Path.of(manifest.getRuntimeRoot());
        requirePrivateDirectory(taskRoot);
        requirePrivateDirectory(taskRoot.resolve("evidence"));
        if (!manifestFile.startsWith(taskRoot)) {
            throw new IllegalArgumentException("XINGYUAN_TARGET_UNSAFE");
        }
        String digest;
        try {
            digest = HexFormat.of().formatHex(
                    MessageDigest.getInstance("SHA-256").digest(manifestBytes));
        } catch (NoSuchAlgorithmException unavailableAlgorithm) {
            throw new IllegalStateException("XINGYUAN_INPUT_UNAVAILABLE");
        }
        var receipt = strictMapper().readValue(
                readProtectedBytes(receiptFile, taskRoot.resolve("evidence"), 128 * 1024),
                IsolatedDatabaseReceiptDTO.class);
        validateDatabaseReceipt(manifest, digest, role, receipt);
        return VerifiedDatabaseInputsBO.builder().manifest(manifest).receipt(receipt)
                .manifestSha256(digest).jdbcUrl("jdbc:postgresql://127.0.0.1:5432/" + receipt.getDatabaseName()).build();
    }

    static void verifyDatabaseConnection(Connection connection, IsolatedDatabaseReceiptDTO receipt)
            throws SQLException {
        try (var query = connection.prepareStatement("""
                SELECT current_database(), host(inet_server_addr()), inet_server_port(),
                       d.oid::bigint, shobj_description(d.oid, 'pg_database'), pg_get_userbyid(d.datdba)
                FROM pg_database d WHERE d.datname = current_database()
                """)) {
            query.setQueryTimeout(5);
            try (var rows = query.executeQuery()) {
                if (!rows.next() || !receipt.getDatabaseName().equals(rows.getString(1))
                        || !"127.0.0.1".equals(rows.getString(2)) || rows.getInt(3) != 5432
                        || receipt.getOid() != rows.getLong(4)
                        || !receipt.getOwnerComment().equals(rows.getString(5))
                        || !receipt.getDatabaseOwner().equals(rows.getString(6)) || rows.next()) {
                    throw new IllegalArgumentException("XINGYUAN_TARGET_UNSAFE");
                }
            }
        }
    }

    static ObjectMapper strictMapper() {
        return Jackson2ObjectMapperBuilder.json()
                .featuresToEnable(JsonParser.Feature.STRICT_DUPLICATE_DETECTION,
                        DeserializationFeature.FAIL_ON_UNKNOWN_PROPERTIES,
                        DeserializationFeature.FAIL_ON_TRAILING_TOKENS,
                        DeserializationFeature.FAIL_ON_NULL_FOR_PRIMITIVES)
                .featuresToDisable(DeserializationFeature.ACCEPT_FLOAT_AS_INT,
                        MapperFeature.ALLOW_COERCION_OF_SCALARS).build();
    }

    static void validateTargets(IsolatedIntegrationManifestDTO manifest, Path repository) {
        try (var factory = Validation.buildDefaultValidatorFactory()) {
            Validator validator = factory.getValidator();
            if (!validator.validate(manifest, Default.class, Prepare.class).isEmpty()) {
                throw new IllegalArgumentException("XINGYUAN_INPUT_INVALID");
            }
        }
        Path expectedRepository = repository.toAbsolutePath().normalize();
        Path taskRoot = expectedRepository.resolve("target/xingyuan-integration-" + manifest.getRunId());
        if (!expectedRepository.toString().equals(manifest.getRepoRoot())
                || !taskRoot.toString().equals(manifest.getRuntimeRoot())) {
            throw new IllegalArgumentException("XINGYUAN_TARGET_UNSAFE");
        }
        if (!"https://127.0.0.1:28443".equals(manifest.getPublicOrigin())
                || !"127.0.0.1:5432".equals(manifest.getPostgres().getEndpoint())
                || !"postgres".equals(manifest.getPostgres().getMaintenanceDatabase())
                || !"redis://127.0.0.1:6379".equals(manifest.getRedis().getEndpoint())
                || !List.of("default", "tenant-b").equals(manifest.getTenantCodes())
                || !"local-two-tenant-users-v1".equals(manifest.getUserRecipe())
                || !"local-explicit-role-fields-v1".equals(manifest.getAuthorizationRecipe())
                || !UUID.fromString(manifest.getRunId()).toString().equals(manifest.getRunId())) {
            throw new IllegalArgumentException("XINGYUAN_TARGET_UNSAFE");
        }
        var roles = new HashSet<String>();
        var names = new HashSet<String>();
        for (DatabaseTargetDTO database : manifest.getDatabases()) {
            if (!database.getName().equals(DATABASE_NAMES.get(database.getRole()))
                    || !roles.add(database.getRole()) || !names.add(database.getName())) {
                throw new IllegalArgumentException("XINGYUAN_TARGET_UNSAFE");
            }
        }
        if (!roles.equals(DATABASE_NAMES.keySet())) {
            throw new IllegalArgumentException("XINGYUAN_TARGET_UNSAFE");
        }
        try {
            if (Long.parseLong(manifest.getPlatformStoragePartitionId()) <= 0L) {
                throw new IllegalArgumentException("XINGYUAN_TARGET_UNSAFE");
            }
        } catch (NumberFormatException invalidPartition) {
            throw new IllegalArgumentException("XINGYUAN_TARGET_UNSAFE");
        }
    }

    private IsolatedIntegrationManifestDTO intent() {
        String runId = UUID.randomUUID().toString();
        String repository = temporaryRepository.toAbsolutePath().normalize().toString();
        String runtime = Path.of(repository).resolve("target/xingyuan-integration-" + runId).toString();
        return IsolatedIntegrationManifestDTO.builder().schemaVersion(1).runId(runId)
                .repoRoot(repository).runtimeRoot(runtime).publicOrigin("https://127.0.0.1:28443")
                .postgres(PostgresTargetDTO.builder().endpoint("127.0.0.1:5432")
                        .maintenanceDatabase("postgres").credentialFile(runtime + "/secrets/postgres.json").build())
                .redis(RedisTargetDTO.builder().endpoint("redis://127.0.0.1:6379")
                        .database(15).credentialFile(runtime + "/secrets/redis.json").build())
                .databases(DATABASE_NAMES.entrySet().stream().map(e -> DatabaseTargetDTO.builder()
                        .role(e.getKey()).name(e.getValue()).build()).toList())
                .platformStoragePartitionId("900000000000000001")
                .tenantCodes(List.of("default", "tenant-b"))
                .userRecipe("local-two-tenant-users-v1").authorizationRecipe("local-explicit-role-fields-v1")
                .processes(List.of()).artifacts(Map.of()).secretFiles(Map.of())
                .deadlines(DeadlineDTO.builder().startupSeconds(300).operationSeconds(900).httpSeconds(30).build())
                .catalogFiles(List.of()).policyFiles(List.of()).build();
    }

    @Data
    @NoArgsConstructor
    @AllArgsConstructor
    @Accessors(chain = true)
    @Builder
    @JsonInclude(JsonInclude.Include.ALWAYS)
    public static class IsolatedIntegrationManifestDTO {
        @Min(1) @Max(1) private int schemaVersion;
        @NotBlank @Pattern(regexp = "[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}") private String runId;
        @NotBlank @Size(max = 4096) private String repoRoot;
        @NotBlank @Size(max = 4096) private String runtimeRoot;
        @NotBlank private String publicOrigin;
        @NotNull @Valid private PostgresTargetDTO postgres;
        @NotNull @Valid private RedisTargetDTO redis;
        @NotNull @Size(min = 9, max = 12) @Valid private List<DatabaseTargetDTO> databases;
        @NotBlank @Pattern(regexp = "[1-9][0-9]{0,18}") private String platformStoragePartitionId;
        @NotNull @Size(min = 2, max = 2) private List<@NotBlank String> tenantCodes;
        @NotBlank private String userRecipe;
        @NotBlank private String authorizationRecipe;
        @NotNull @Size(max = 32) @Valid private List<ProcessTargetDTO> processes;
        @NotNull @Size(max = 32) @Valid private Map<@NotBlank String, ArtifactReferenceDTO> artifacts;
        @NotNull @Size(max = 32) private Map<@NotBlank String, @NotBlank String> secretFiles;
        @NotNull @Valid private DeadlineDTO deadlines;
        @NotNull @Size(max = 32) @Valid private List<FileReferenceDTO> catalogFiles;
        @NotNull @Size(max = 32) @Valid private List<FileReferenceDTO> policyFiles;
    }

    @Data
    @NoArgsConstructor
    @AllArgsConstructor
    @Accessors(chain = true)
    @Builder
    @JsonInclude(JsonInclude.Include.ALWAYS)
    public static class PostgresTargetDTO {
        @NotBlank private String endpoint;
        @NotBlank private String maintenanceDatabase;
        @NotBlank @Size(max = 4096) private String credentialFile;
    }

    @Data
    @NoArgsConstructor
    @AllArgsConstructor
    @Accessors(chain = true)
    @Builder
    @JsonInclude(JsonInclude.Include.ALWAYS)
    public static class RedisTargetDTO {
        @NotBlank private String endpoint;
        @Min(1) @Max(15) private int database;
        @NotBlank @Size(max = 4096) private String credentialFile;
    }

    @Data
    @NoArgsConstructor
    @AllArgsConstructor
    @Accessors(chain = true)
    @Builder
    @JsonInclude(JsonInclude.Include.ALWAYS)
    public static class DatabaseTargetDTO {
        @NotBlank private String role;
        @NotBlank @Pattern(regexp = "[a-z][a-z0-9_]{0,62}") private String name;
    }

    @Data
    @NoArgsConstructor
    @AllArgsConstructor
    @Accessors(chain = true)
    @Builder
    @JsonInclude(JsonInclude.Include.ALWAYS)
    public static class ProcessTargetDTO {
        @NotBlank private String id;
        @NotBlank private String artifactRole;
        @NotBlank @Pattern(regexp = "JAVA|NODE|NGINX") private String kind;
        @Min(1) @Max(65535) private int port;
        @Builder.Default @Size(max = 2) private List<@Min(1) @Max(65535) Integer> additionalPorts = List.of();
    }

    @Data
    @NoArgsConstructor
    @AllArgsConstructor
    @Accessors(chain = true)
    @Builder
    @JsonInclude(JsonInclude.Include.ALWAYS)
    public static class ArtifactReferenceDTO {
        @NotBlank @Size(max = 4096) private String path;
        @NotBlank @Pattern(regexp = "[0-9a-f]{64}") private String sha256;
        @NotBlank @Size(max = 128) private String buildId;
    }

    @Data
    @NoArgsConstructor
    @AllArgsConstructor
    @Accessors(chain = true)
    @Builder
    @JsonInclude(JsonInclude.Include.ALWAYS)
    public static class FileReferenceDTO {
        @NotBlank @Size(max = 4096) private String path;
        @NotBlank @Pattern(regexp = "[0-9a-f]{64}") private String sha256;
    }

    @Data
    @NoArgsConstructor
    @AllArgsConstructor
    @Accessors(chain = true)
    @Builder
    @JsonInclude(JsonInclude.Include.ALWAYS)
    public static class DeadlineDTO {
        @Min(1) @Max(300) private int startupSeconds;
        @Min(1) @Max(900) private int operationSeconds;
        @Min(1) @Max(30) private int httpSeconds;
    }

    @Data
    @NoArgsConstructor
    @AllArgsConstructor
    @Accessors(chain = true)
    @Builder
    public static class IsolatedDatabaseReceiptDTO {
        @NotBlank private String runId;
        @NotBlank @Pattern(regexp = "[0-9a-f]{64}") private String manifestSha256;
        @NotBlank private String role;
        @NotBlank private String databaseName;
        @Min(1) private long oid;
        @NotBlank private String ownerComment;
        @NotBlank private String databaseOwner;
    }

    @Data
    @NoArgsConstructor
    @AllArgsConstructor
    @Accessors(chain = true)
    @Builder
    public static class VerifiedDatabaseInputsBO {
        private IsolatedIntegrationManifestDTO manifest;
        private IsolatedDatabaseReceiptDTO receipt;
        private String manifestSha256;
        private String jdbcUrl;
    }

    /** Task catalog resources are standalone APIs; require their reviewed tuples without widening that task contract. */
    static void validateNativeApplicationSnapshot(
            top.egon.cola.platform.tianquan.jianshen.contract.authorization.AppAuthorizationContext app,
            NativeCatalogPreparationBO preparation, NativeCatalogFactsBO facts, NativeRoleAssignmentProofVO proof,
            top.egon.cola.platform.tianquan.jianshen.contract.authorization.UserAuthorizationSnapshot snapshot, String userKey) {
        var selected = preparation.getReview().getRoles().stream().filter(role -> userKey.equals(role.getUserKey())).toList();
        String applicationId = facts.getRegistration().applicationId(); String applicationCode = facts.getRegistration().applicationCode();
        if (selected.size() != 1 || !applicationId.equals(app.applicationId()) || !applicationCode.equals(app.applicationCode())
                || !applicationCode.equals(preparation.getCatalog().getApplicationCode()) || !proof.userId().equals(snapshot.rbacUserId())
                || snapshot.authVersion() < proof.authVersion() || !app.activationRootRoleIds().equals(List.of(proof.roleId()))
                || !app.effectiveRoleIds().equals(List.of(proof.roleId())) || !app.eligibleAssignmentIds().equals(List.of(proof.assignmentId()))) {
            throw new IllegalStateException("XINGYUAN_PARTIAL");
        }
        for (var entry : facts.getResources().entrySet()) {
            var resource = entry.getValue();
            if (!entry.getKey().equals(resource.resourceCode()) || !applicationId.equals(resource.applicationId())
                    || !"API".equals(resource.resourceType()) || resource.parentResourceId() != null || !"ACTIVE".equals(resource.status())) {
                throw new IllegalStateException("XINGYUAN_PARTIAL");
            }
        }
        var role = selected.getFirst(); Set<String> expectedResources = new HashSet<>(role.getResourceCodes());
        Set<String> expectedPermissions = new HashSet<>();
        for (String resourceCode : expectedResources) {
            var resource = facts.getResources().get(resourceCode);
            String permissionCode = preparation.getReview().getResourcePermissions().get(resourceCode);
            var permission = permissionCode == null ? null : facts.getPermissions().get(permissionCode);
            if (resource == null || !"CONFIGURED".equals(resource.mappingStatus()) || permission == null
                    || !permissionCode.equals(permission.permissionCode()) || !applicationId.equals(permission.applicationId())
                    || !"ACTIVE".equals(permission.status()) || !preparation.getReview().getApprovedPermissionCodes().contains(permissionCode)) {
                throw new IllegalStateException("XINGYUAN_PARTIAL");
            }
            expectedPermissions.add(permissionCode);
        }
        if (expectedResources.size() != role.getResourceCodes().size() || app.resourceCodes().size() != expectedResources.size()
                || !expectedResources.equals(new HashSet<>(app.resourceCodes())) || !expectedPermissions.equals(app.permissions())) {
            throw new IllegalStateException("XINGYUAN_PARTIAL");
        }
        Map<String, Map<String, FieldAccessLevel>> expectedFields = new LinkedHashMap<>();
        List<FieldAccessLevel> levels = List.of(FieldAccessLevel.NONE, FieldAccessLevel.MASKED_READ, FieldAccessLevel.READ, FieldAccessLevel.WRITE);
        for (var rule : role.getFieldRules()) {
            var resource = facts.getResources().get(rule.getResourceCode());
            var definition = facts.getFields().get(List.of(rule.getResourceCode(), rule.getFieldCode()));
            if (!expectedResources.contains(rule.getResourceCode()) || resource == null || definition == null
                    || !applicationId.equals(definition.applicationId()) || !resource.resourceId().equals(definition.resourceId())
                    || !rule.getFieldCode().equals(definition.fieldCode()) || !"ACTIVE".equals(definition.status())) {
                throw new IllegalStateException("XINGYUAN_PARTIAL");
            }
            FieldAccessLevel cap = definition.writable() ? FieldAccessLevel.WRITE : FieldAccessLevel.valueOf(definition.defaultAccess());
            FieldAccessLevel requested = FieldAccessLevel.valueOf(rule.getAccessLevel());
            FieldAccessLevel effective = levels.get(Math.min(levels.indexOf(requested), levels.indexOf(cap)));
            String permission = preparation.getReview().getResourcePermissions().get(rule.getResourceCode());
            String key = permission + ':' + applicationCode + ':' + rule.getResourceCode();
            if (expectedFields.computeIfAbsent(key, ignored -> new LinkedHashMap<>()).putIfAbsent(rule.getFieldCode(), effective) != null) {
                throw new IllegalStateException("XINGYUAN_PARTIAL");
            }
        }
        if (!expectedFields.keySet().equals(app.fieldPolicies().keySet())) { throw new IllegalStateException("XINGYUAN_PARTIAL"); }
        for (var entry : expectedFields.entrySet()) {
            var decision = app.fieldPolicies().get(entry.getKey());
            String permission = preparation.getReview().getResourcePermissions().get(decision.resourceCode());
            if (decision.decision() != top.egon.cola.platform.tianquan.jianshen.contract.authorization.Decision.ALLOW
                    || !"ALLOW".equals(decision.reasonCode()) || !snapshot.tenantId().equals(decision.tenantId())
                    || !snapshot.rbacUserId().equals(decision.subjectId()) || !applicationCode.equals(decision.applicationCode())
                    || !Objects.equals(permission, decision.permissionCode()) || !expectedResources.contains(decision.resourceCode())
                    || !entry.getKey().equals(decision.permissionCode() + ':' + applicationCode + ':' + decision.resourceCode())
                    || snapshot.authVersion() != decision.authVersion() || snapshot.policyVersion() != decision.policyVersion()
                    || !snapshot.generatedAt().equals(decision.decidedAt()) || !entry.getValue().keySet().equals(decision.fields().keySet())) {
                throw new IllegalStateException("XINGYUAN_PARTIAL");
            }
            for (var field : entry.getValue().entrySet()) {
                if (field.getValue() != decision.fields().get(field.getKey()).level()) { throw new IllegalStateException("XINGYUAN_PARTIAL"); }
            }
        }
    }

    @Test
    void nativeApplicationSnapshotUsesOriginalProjectionAndDefinitionCaps() {
        var fixture = nativeApplicationSnapshotFixture(); var snapshot = fixture.snapshot(); var app = snapshot.appContexts().getFirst();
        org.junit.jupiter.api.Assertions.assertDoesNotThrow(() -> validateNativeApplicationSnapshot(
                app, fixture.preparation(), fixture.facts(), fixture.proof(), snapshot, "viewer"));
        assertThat(snapshot.checksum()).startsWith("sha256:");
        assertThat(app.fieldPolicies()).containsOnlyKeys("native-test:read:native-test:native-test.read", "native-test:write:native-test:native-test.write");
        assertThat(app.fieldPolicies().get("native-test:read:native-test:native-test.read").fields()).containsOnlyKeys("label");
        assertThat(app.fieldPolicies().get("native-test:read:native-test:native-test.read").fields().get("label").level()).isEqualTo(FieldAccessLevel.MASKED_READ);
        assertThat(app.fieldPolicies().get("native-test:write:native-test:native-test.write").fields().get("secret").level()).isEqualTo(FieldAccessLevel.WRITE);
    }

    @Test
    void nativeApplicationSnapshotRejectsForeignRoleAssignmentPermissionAndResource() {
        var fixture = nativeApplicationSnapshotFixture(); var snapshot = fixture.snapshot(); var app = snapshot.appContexts().getFirst();
        var invalid = List.of(
                new top.egon.cola.platform.tianquan.jianshen.contract.authorization.AppAuthorizationContext("602", app.applicationCode(), app.activationRootRoleIds(), app.eligibleAssignmentIds(), app.effectiveRoleIds(), app.permissions(), app.dataScopes(), app.fieldPolicies(), app.resourceCodes(), null),
                new top.egon.cola.platform.tianquan.jianshen.contract.authorization.AppAuthorizationContext(app.applicationId(), "foreign", app.activationRootRoleIds(), app.eligibleAssignmentIds(), app.effectiveRoleIds(), app.permissions(), app.dataScopes(), app.fieldPolicies(), app.resourceCodes(), null),
                new top.egon.cola.platform.tianquan.jianshen.contract.authorization.AppAuthorizationContext(app.applicationId(), app.applicationCode(), List.of("502"), app.eligibleAssignmentIds(), app.effectiveRoleIds(), app.permissions(), app.dataScopes(), app.fieldPolicies(), app.resourceCodes(), null),
                new top.egon.cola.platform.tianquan.jianshen.contract.authorization.AppAuthorizationContext(app.applicationId(), app.applicationCode(), app.activationRootRoleIds(), List.of("902"), app.effectiveRoleIds(), app.permissions(), app.dataScopes(), app.fieldPolicies(), app.resourceCodes(), null),
                new top.egon.cola.platform.tianquan.jianshen.contract.authorization.AppAuthorizationContext(app.applicationId(), app.applicationCode(), app.activationRootRoleIds(), app.eligibleAssignmentIds(), List.of("501", "502"), app.permissions(), app.dataScopes(), app.fieldPolicies(), app.resourceCodes(), null),
                new top.egon.cola.platform.tianquan.jianshen.contract.authorization.AppAuthorizationContext(app.applicationId(), app.applicationCode(), app.activationRootRoleIds(), app.eligibleAssignmentIds(), app.effectiveRoleIds(), Set.of("native-test:read"), app.dataScopes(), app.fieldPolicies(), app.resourceCodes(), null),
                new top.egon.cola.platform.tianquan.jianshen.contract.authorization.AppAuthorizationContext(app.applicationId(), app.applicationCode(), app.activationRootRoleIds(), app.eligibleAssignmentIds(), app.effectiveRoleIds(), Set.of("native-test:read", "native-test:write", "foreign:write"), app.dataScopes(), app.fieldPolicies(), app.resourceCodes(), null),
                new top.egon.cola.platform.tianquan.jianshen.contract.authorization.AppAuthorizationContext(app.applicationId(), app.applicationCode(), app.activationRootRoleIds(), app.eligibleAssignmentIds(), app.effectiveRoleIds(), app.permissions(), app.dataScopes(), app.fieldPolicies(), List.of("native-test.read"), null));
        for (var changed : invalid) {
            assertThatThrownBy(() -> validateNativeApplicationSnapshot(changed, fixture.preparation(), fixture.facts(), fixture.proof(), snapshot, "viewer"))
                    .hasMessage("XINGYUAN_PARTIAL");
        }
        assertThatThrownBy(() -> validateNativeApplicationSnapshot(app, fixture.preparation(), fixture.facts(), fixture.proof(), snapshot, "admin"))
                .hasMessage("XINGYUAN_PARTIAL");
        var foreignUser = new top.egon.cola.platform.tianquan.jianshen.contract.authorization.UserAuthorizationSnapshot(snapshot.systemCode(), snapshot.tenantId(), snapshot.identitySub(), "302",
                snapshot.authVersion(), snapshot.policyVersion(), snapshot.appContexts(), snapshot.checksum(), snapshot.generatedAt(), snapshot.expiresAt());
        assertThatThrownBy(() -> validateNativeApplicationSnapshot(app, fixture.preparation(), fixture.facts(), fixture.proof(), foreignUser, "viewer"))
                .hasMessage("XINGYUAN_PARTIAL");
    }

    @Test
    void nativeApplicationSnapshotRejectsForeignFieldTuplesIdentityVersionsAndEscalation() {
        var fixture = nativeApplicationSnapshotFixture(); var snapshot = fixture.snapshot(); var app = snapshot.appContexts().getFirst();
        String readKey = "native-test:read:native-test:native-test.read"; var decision = app.fieldPolicies().get(readKey);
        var invalid = List.of(
                new top.egon.cola.platform.tianquan.jianshen.contract.authorization.FieldPolicyDecision(decision.decision(), decision.reasonCode(), "1002", decision.subjectId(), decision.permissionCode(), decision.applicationCode(), decision.resourceCode(), decision.fields(), decision.authVersion(), decision.policyVersion(), decision.evidenceIds(), decision.decidedAt()),
                new top.egon.cola.platform.tianquan.jianshen.contract.authorization.FieldPolicyDecision(decision.decision(), decision.reasonCode(), decision.tenantId(), "302", decision.permissionCode(), decision.applicationCode(), decision.resourceCode(), decision.fields(), decision.authVersion(), decision.policyVersion(), decision.evidenceIds(), decision.decidedAt()),
                new top.egon.cola.platform.tianquan.jianshen.contract.authorization.FieldPolicyDecision(decision.decision(), decision.reasonCode(), decision.tenantId(), decision.subjectId(), decision.permissionCode(), "foreign", decision.resourceCode(), decision.fields(), decision.authVersion(), decision.policyVersion(), decision.evidenceIds(), decision.decidedAt()),
                new top.egon.cola.platform.tianquan.jianshen.contract.authorization.FieldPolicyDecision(decision.decision(), decision.reasonCode(), decision.tenantId(), decision.subjectId(), "native-test:write", decision.applicationCode(), decision.resourceCode(), decision.fields(), decision.authVersion(), decision.policyVersion(), decision.evidenceIds(), decision.decidedAt()),
                new top.egon.cola.platform.tianquan.jianshen.contract.authorization.FieldPolicyDecision(decision.decision(), decision.reasonCode(), decision.tenantId(), decision.subjectId(), decision.permissionCode(), decision.applicationCode(), "native-test.write", decision.fields(), decision.authVersion(), decision.policyVersion(), decision.evidenceIds(), decision.decidedAt()),
                new top.egon.cola.platform.tianquan.jianshen.contract.authorization.FieldPolicyDecision(decision.decision(), decision.reasonCode(), decision.tenantId(), decision.subjectId(), decision.permissionCode(), decision.applicationCode(), decision.resourceCode(), decision.fields(), decision.authVersion() + 1L, decision.policyVersion(), decision.evidenceIds(), decision.decidedAt()),
                new top.egon.cola.platform.tianquan.jianshen.contract.authorization.FieldPolicyDecision(decision.decision(), decision.reasonCode(), decision.tenantId(), decision.subjectId(), decision.permissionCode(), decision.applicationCode(), decision.resourceCode(), decision.fields(), decision.authVersion(), decision.policyVersion() + 1L, decision.evidenceIds(), decision.decidedAt()),
                new top.egon.cola.platform.tianquan.jianshen.contract.authorization.FieldPolicyDecision(top.egon.cola.platform.tianquan.jianshen.contract.authorization.Decision.DENY, "DENY", decision.tenantId(), decision.subjectId(), decision.permissionCode(), decision.applicationCode(), decision.resourceCode(), decision.fields(), decision.authVersion(), decision.policyVersion(), decision.evidenceIds(), decision.decidedAt()),
                new top.egon.cola.platform.tianquan.jianshen.contract.authorization.FieldPolicyDecision(decision.decision(), decision.reasonCode(), decision.tenantId(), decision.subjectId(), decision.permissionCode(), decision.applicationCode(), decision.resourceCode(), Map.of("label", new top.egon.cola.platform.tianquan.jianshen.contract.authorization.FieldPolicyDecision.FieldAccess(FieldAccessLevel.WRITE, null)), decision.authVersion(), decision.policyVersion(), decision.evidenceIds(), decision.decidedAt()),
                new top.egon.cola.platform.tianquan.jianshen.contract.authorization.FieldPolicyDecision(decision.decision(), decision.reasonCode(), decision.tenantId(), decision.subjectId(), decision.permissionCode(), decision.applicationCode(), decision.resourceCode(), Map.of(), decision.authVersion(), decision.policyVersion(), decision.evidenceIds(), decision.decidedAt()));
        for (var changed : invalid) {
            var policies = new LinkedHashMap<>(app.fieldPolicies()); policies.put(readKey, changed);
            assertThatThrownBy(() -> validateNativeApplicationSnapshot(nativeSnapshotWithFields(app, policies), fixture.preparation(), fixture.facts(), fixture.proof(), snapshot, "viewer"))
                    .hasMessage("XINGYUAN_PARTIAL");
        }
        var wrongTuple = new LinkedHashMap<>(app.fieldPolicies()); wrongTuple.put("native-test:write:native-test:native-test.read", decision);
        assertThatThrownBy(() -> validateNativeApplicationSnapshot(nativeSnapshotWithFields(app, wrongTuple), fixture.preparation(), fixture.facts(), fixture.proof(), snapshot, "viewer"))
                .hasMessage("XINGYUAN_PARTIAL");
        var missingTuple = new LinkedHashMap<>(app.fieldPolicies()); missingTuple.remove(readKey);
        assertThatThrownBy(() -> validateNativeApplicationSnapshot(nativeSnapshotWithFields(app, missingTuple), fixture.preparation(), fixture.facts(), fixture.proof(), snapshot, "viewer"))
                .hasMessage("XINGYUAN_PARTIAL");
    }

    @Test
    void nativeApplicationSnapshotRejectsUnexpectedCatalogHierarchyAndResourceKind() {
        var fixture = nativeApplicationSnapshotFixture(); var snapshot = fixture.snapshot(); var app = snapshot.appContexts().getFirst();
        var resource = fixture.facts().getResources().get("native-test.read");
        for (var changed : List.of(
                new ResourceVO(resource.resourceId(), resource.applicationId(), "ROUTE", resource.resourceCode(), resource.resourceName(), null, resource.mappingStatus(), resource.status(), resource.version()),
                new ResourceVO(resource.resourceId(), resource.applicationId(), "API", resource.resourceCode(), resource.resourceName(), "799", resource.mappingStatus(), resource.status(), resource.version()))) {
            var resources = new LinkedHashMap<>(fixture.facts().getResources()); resources.put(resource.resourceCode(), changed);
            var facts = NativeCatalogFactsBO.builder().registration(fixture.facts().getRegistration()).permissions(fixture.facts().getPermissions())
                    .resources(resources).fields(fixture.facts().getFields()).build();
            assertThatThrownBy(() -> validateNativeApplicationSnapshot(app, fixture.preparation(), facts, fixture.proof(), snapshot, "viewer"))
                    .hasMessage("XINGYUAN_PARTIAL");
        }
    }

    private static top.egon.cola.platform.tianquan.jianshen.contract.authorization.AppAuthorizationContext nativeSnapshotWithFields(
            top.egon.cola.platform.tianquan.jianshen.contract.authorization.AppAuthorizationContext app,
            Map<String, top.egon.cola.platform.tianquan.jianshen.contract.authorization.FieldPolicyDecision> fields) {
        return new top.egon.cola.platform.tianquan.jianshen.contract.authorization.AppAuthorizationContext(app.applicationId(), app.applicationCode(),
                app.activationRootRoleIds(), app.eligibleAssignmentIds(), app.effectiveRoleIds(), app.permissions(), app.dataScopes(), fields, app.resourceCodes(), app.landingRouteCode());
    }

    @Data @NoArgsConstructor @AllArgsConstructor @Accessors(fluent = true, chain = true) @Builder
    private static class NativeApplicationSnapshotFixtureVO {
        private NativeCatalogPreparationBO preparation;
        private NativeCatalogFactsBO facts;
        private NativeRoleAssignmentProofVO proof;
        private top.egon.cola.platform.tianquan.jianshen.contract.authorization.UserAuthorizationSnapshot snapshot;
    }

    private static NativeApplicationSnapshotFixtureVO nativeApplicationSnapshotFixture() {
        Instant now = Instant.parse("2026-10-15T00:00:00Z");
        var role = NativeRoleReviewDTO.builder().userKey("viewer").roleCode("XINGYUAN_VIEWER")
                .resourceCodes(List.of("native-test.read", "native-test.write")).fieldRules(List.of(
                        NativeFieldAccessDTO.builder().resourceCode("native-test.read").fieldCode("label").accessLevel("READ").build(),
                        NativeFieldAccessDTO.builder().resourceCode("native-test.write").fieldCode("secret").accessLevel("WRITE").build())).build();
        var preparation = NativeCatalogPreparationBO.builder().catalog(DeploymentCatalogRegistrationCommand.builder().applicationCode("native-test").build())
                .review(NativeApplicationReviewDTO.builder().processId("native-light").approvedPermissionCodes(List.of("native-test:read", "native-test:write"))
                        .resourcePermissions(Map.of("native-test.read", "native-test:read", "native-test.write", "native-test:write")).roles(List.of(role)).build()).build();
        var facts = NativeCatalogFactsBO.builder().registration(new DeploymentCatalogRegistrationResultVO("601", "native-test", "build", "a".repeat(64), 1L, 2, 2, 3, "REGISTERED_PENDING_REVIEW"))
                .permissions(Map.of("native-test:read", new PermissionCatalogVO("801", "601", "native-test:read", "Read", "LOW", "ACTIVE", "DEPLOYMENT", "build", "a".repeat(64), 1L),
                        "native-test:write", new PermissionCatalogVO("802", "601", "native-test:write", "Write", "LOW", "ACTIVE", "DEPLOYMENT", "build", "a".repeat(64), 1L)))
                .resources(Map.of("native-test.read", new ResourceVO("701", "601", "API", "native-test.read", "Read", null, "CONFIGURED", "ACTIVE", 1L),
                        "native-test.write", new ResourceVO("702", "601", "API", "native-test.write", "Write", null, "CONFIGURED", "ACTIVE", 1L)))
                .fields(Map.of(List.of("native-test.read", "label"), new FieldDefinitionVO("1001", "601", "701", "label", "$.label", "STRING", "NORMAL", "MASKED_READ", "REDACT", false, false, "ACTIVE", 1L),
                        List.of("native-test.read", "unselected"), new FieldDefinitionVO("1002", "601", "701", "unselected", "$.unselected", "STRING", "NORMAL", "NONE", null, true, false, "ACTIVE", 1L),
                        List.of("native-test.write", "secret"), new FieldDefinitionVO("1003", "601", "702", "secret", "$.secret", "STRING", "NORMAL", "NONE", null, true, false, "ACTIVE", 1L))).build();
        var proof = new NativeRoleAssignmentProofVO("301", "501", 2L, "a".repeat(64), "901", "mutation", 3L, "1101", "policy", 1L,
                now.minusSeconds(60), now.plusSeconds(540), now.minusSeconds(30), now.plusSeconds(28770));
        var hierarchy = new top.egon.cola.platform.tianquan.jianshen.core.hierarchy.RoleHierarchy(List.of(
                new top.egon.cola.platform.tianquan.jianshen.core.hierarchy.RoleNode("501", "601", "XINGYUAN_VIEWER", true,
                        top.egon.cola.platform.tianquan.jianshen.core.hierarchy.RoleNode.RiskLevel.LOW, false, null, 0)), List.of());
        var rules = new top.egon.cola.platform.tianquan.jianshen.core.activation.AuthorizationRuleFacts(
                List.of(new top.egon.cola.platform.tianquan.jianshen.core.activation.AuthorizationRuleFacts.ResourceGrantBinding("501", "701", "native-test.read", "API", "native-test:read"),
                        new top.egon.cola.platform.tianquan.jianshen.core.activation.AuthorizationRuleFacts.ResourceGrantBinding("501", "702", "native-test.write", "API", "native-test:write")), List.of(),
                List.of(new top.egon.cola.platform.tianquan.jianshen.core.activation.AuthorizationRuleFacts.FieldRuleFact("501", "native-test.read", "label", FieldAccessLevel.READ),
                        new top.egon.cola.platform.tianquan.jianshen.core.activation.AuthorizationRuleFacts.FieldRuleFact("501", "native-test.write", "secret", FieldAccessLevel.WRITE)),
                List.of(new top.egon.cola.platform.tianquan.jianshen.core.activation.AuthorizationRuleFacts.FieldDefinitionFact("native-test.read", "label", FieldAccessLevel.MASKED_READ),
                        new top.egon.cola.platform.tianquan.jianshen.core.activation.AuthorizationRuleFacts.FieldDefinitionFact("native-test.read", "unselected", FieldAccessLevel.WRITE),
                        new top.egon.cola.platform.tianquan.jianshen.core.activation.AuthorizationRuleFacts.FieldDefinitionFact("native-test.write", "secret", FieldAccessLevel.WRITE)),
                List.of(new top.egon.cola.platform.tianquan.jianshen.core.activation.AuthorizationRuleFacts.ResourceFact("701", "native-test.read", "API", null, "native-test:read"),
                        new top.egon.cola.platform.tianquan.jianshen.core.activation.AuthorizationRuleFacts.ResourceFact("702", "native-test.write", "API", null, "native-test:write")));
        var source = new top.egon.cola.platform.tianquan.jianshen.admin.authorization.runtime.activation.domain.vo.ActivationFactsVO("1001", "301", hierarchy,
                List.of(new top.egon.cola.platform.tianquan.jianshen.core.activation.EligibleAssignmentFact("901", "301", "501",
                        top.egon.cola.platform.tianquan.jianshen.core.activation.EligibleAssignmentFact.Status.ACTIVE, now.minusSeconds(30), now.plusSeconds(28770))),
                List.of(), rules, 3L, 4L, "directory:1", Map.of("601", new top.egon.cola.platform.tianquan.jianshen.admin.authorization.runtime.activation.domain.vo.ApplicationFactVO("601", "native-test", "Native test")), Map.of("501", "Viewer"));
        var built = new top.egon.cola.platform.tianquan.jianshen.core.decision.UserAuthorizationSnapshotBuilder().build(Set.of("501"), hierarchy, rules, 3L, 4L, 4L);
        var resolution = new top.egon.cola.platform.tianquan.jianshen.core.activation.RoleActivationResolution(
                new top.egon.cola.platform.tianquan.jianshen.core.activation.ActiveRoleSet("1001", "301", Map.of("601", Set.of("501")), built.checksum()), built, List.of("901"));
        var snapshot = new UserAuthorizationSnapshotProjector().project(new top.egon.cola.platform.tianquan.jianshen.admin.authorization.runtime.domain.dto.ProjectionCommandDTO(
                "1001", "private-subject", "301", 4L, 4L, now.plusSeconds(600), resolution, source, now)).snapshot();
        return new NativeApplicationSnapshotFixtureVO(preparation, facts, proof, snapshot);
    }

}
