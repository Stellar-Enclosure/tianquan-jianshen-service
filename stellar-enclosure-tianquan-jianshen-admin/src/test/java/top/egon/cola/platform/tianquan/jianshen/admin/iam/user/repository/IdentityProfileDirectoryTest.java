package top.egon.cola.platform.tianquan.jianshen.admin.iam.user.repository;

import org.junit.jupiter.api.Test;
import top.egon.cola.component.rpc.annotation.EgonRpcReference;
import top.egon.cola.platform.tianquan.shoubing.rpc.contract.IdentityDirectoryRpc;
import top.egon.cola.platform.tianquan.shoubing.rpc.contract.proto.v1.BatchGetIdentityProfilesRequest;
import top.egon.cola.platform.tianquan.shoubing.rpc.contract.proto.v1.BatchGetIdentityProfilesResponse;
import top.egon.cola.platform.tianquan.shoubing.rpc.contract.proto.v1.IdentityProfile;

import java.lang.reflect.Field;
import java.util.List;
import java.util.Set;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.verifyNoInteractions;
import static org.mockito.Mockito.when;

class IdentityProfileDirectoryTest {

    @Test
    void usesTheSameApprovedShoubingBindingWithoutRetryForOptionalProfiles() throws NoSuchFieldException {
        Field field = IdentityProfileDirectory.class.getDeclaredField("rpc");
        EgonRpcReference reference = field.getAnnotation(EgonRpcReference.class);

        assertThat(reference).isNotNull();
        assertThat(reference.bindingId())
                .isEqualTo("shoubing-identity-directory");
        assertThat(reference.group())
                .isEqualTo("tianquan-shoubing");
        assertThat(reference.version())
                .isEqualTo("1.0.0");
        assertThat(reference.timeoutMs()).isEqualTo(1500);
        assertThat(reference.retries()).isEqualTo(0);
    }

    @Test
    void returnsEnrichedProfilesAndMissingMarker() {
        IdentityDirectoryRpc rpc = mock(IdentityDirectoryRpc.class);
        when(rpc.batchGetIdentityProfiles(any(BatchGetIdentityProfilesRequest.class)))
                .thenReturn(BatchGetIdentityProfilesResponse.newBuilder()
                        .addProfiles(IdentityProfile.newBuilder()
                                .setSubject("subject-a")
                                .setUsername("alice")
                                .setDisplayName("Alice")
                                .setStatus("ACTIVE")
                                .setVersion(3L))
                        .addMissingSubjects("subject-missing")
                        .build());

        IdentityProfileDirectory directory = new IdentityProfileDirectory(rpc);
        IdentityProfileDirectory.BatchResult result = directory.batchGet(
                List.of("subject-a", "subject-missing"));

        assertThat(result.available()).isTrue();
        assertThat(result.profiles()).containsKey("subject-a");
        assertThat(result.profiles().get("subject-a").displayName())
                .isEqualTo("Alice");
        assertThat(result.missingSubjects())
                .containsExactly("subject-missing");
    }

    @Test
    void keepsAuthorizationUsableWhenIdentityDirectoryIsUnavailable() {
        IdentityDirectoryRpc rpc = mock(IdentityDirectoryRpc.class);
        when(rpc.batchGetIdentityProfiles(any(BatchGetIdentityProfilesRequest.class)))
                .thenThrow(new IllegalStateException("idp unavailable"));

        IdentityProfileDirectory directory = new IdentityProfileDirectory(rpc);
        IdentityProfileDirectory.BatchResult result = directory.batchGet(
                Set.of("subject-a"));

        assertThat(result.available()).isFalse();
        assertThat(result.profiles()).isEmpty();
        assertThat(result.missingSubjects()).isEmpty();
    }

    @Test
    void treatsMissingRpcBindingAsUnavailable() {
        IdentityProfileDirectory directory = new IdentityProfileDirectory();

        assertThat(directory.batchGet(List.of("subject-a")).available())
                .isFalse();
    }

    @Test
    void rejectsInvalidOrOversizedSubjectsWithoutOpeningAnRpc() {
        IdentityDirectoryRpc rpc = mock(IdentityDirectoryRpc.class);
        IdentityProfileDirectory directory = new IdentityProfileDirectory(rpc);

        assertThat(directory.batchGet(List.of()).available()).isTrue();
        assertThatThrownBy(() -> directory.batchGet(List.of("subject-a", "subject-a")))
                .isInstanceOf(IllegalArgumentException.class);
        assertThatThrownBy(() -> directory.batchGet(List.of(" subject-a")))
                .isInstanceOf(IllegalArgumentException.class);
        assertThatThrownBy(() -> directory.batchGet(java.util.stream.IntStream.range(0, 101)
                .mapToObj(index -> "subject-" + index).toList()))
                .isInstanceOf(IllegalArgumentException.class);
        verifyNoInteractions(rpc);
    }

    @Test
    void treatsAnIncompleteOrDuplicateReplyAsUnavailable() {
        IdentityDirectoryRpc rpc = mock(IdentityDirectoryRpc.class);
        when(rpc.batchGetIdentityProfiles(any(BatchGetIdentityProfilesRequest.class)))
                .thenReturn(BatchGetIdentityProfilesResponse.newBuilder()
                        .addMissingSubjects("subject-a")
                        .build())
                .thenReturn(BatchGetIdentityProfilesResponse.newBuilder()
                        .addMissingSubjects("subject-a")
                        .addMissingSubjects("subject-a")
                        .addMissingSubjects("subject-b")
                        .build());
        IdentityProfileDirectory directory = new IdentityProfileDirectory(rpc);

        assertThat(directory.batchGet(List.of("subject-a", "subject-b")).available()).isFalse();
        assertThat(directory.batchGet(List.of("subject-a", "subject-b")).available()).isFalse();
    }
}
