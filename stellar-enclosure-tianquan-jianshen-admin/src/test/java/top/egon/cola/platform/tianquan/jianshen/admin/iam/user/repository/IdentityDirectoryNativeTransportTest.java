package top.egon.cola.platform.tianquan.jianshen.admin.iam.user.repository;

import io.grpc.ConnectivityState;
import io.grpc.Context;
import io.grpc.Grpc;
import io.grpc.ManagedChannel;
import io.grpc.Metadata;
import io.grpc.Server;
import io.grpc.ServerCall;
import io.grpc.ServerCallHandler;
import io.grpc.ServerInterceptor;
import io.grpc.Status;
import io.grpc.netty.shaded.io.grpc.netty.NettyChannelBuilder;
import io.grpc.netty.shaded.io.grpc.netty.NettyServerBuilder;
import io.grpc.stub.StreamObserver;
import jakarta.validation.Validation;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.Timeout;
import org.springframework.boot.context.properties.bind.Binder;
import org.springframework.boot.env.YamlPropertySourceLoader;
import org.springframework.core.io.ClassPathResource;
import org.springframework.mock.env.MockEnvironment;
import org.springframework.security.core.context.SecurityContext;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.oauth2.core.OAuth2AccessToken;
import top.egon.cola.platform.tianquan.jianshen.admin.config.runtime.Rbac3IdentityDirectoryTenantResolver;
import top.egon.cola.platform.tianquan.jianshen.admin.shared.tenant.domain.TenantContext;
import top.egon.cola.platform.tianquan.jianshen.contract.authorization.SystemAuthorizationSnapshot;
import top.egon.cola.platform.tianquan.jianshen.starter.security.Rbac3AuthenticationToken;
import top.egon.cola.platform.tianquan.jianshen.starter.security.Rbac3UserDetails;
import top.egon.cola.platform.tianquan.shoubing.contract.AuthenticationContext;
import top.egon.cola.platform.tianquan.shoubing.contract.IdentityPrincipal;
import top.egon.cola.platform.tianquan.shoubing.contract.ServiceTokenContext;
import top.egon.cola.platform.tianquan.shoubing.starter.autoconfigure.IdpStarterProperties;
import top.egon.cola.platform.tianquan.shoubing.starter.client.IdpServiceOAuth2Client;
import top.egon.cola.platform.tianquan.shoubing.starter.client.IdpServiceTokenRequest;
import top.egon.cola.platform.tianquan.shoubing.starter.security.domain.TokenAuditProofBO;
import top.egon.cola.platform.tianquan.shoubing.starter.security.rpc.IdpRpcClientCredentialInterceptorFactory;
import top.egon.cola.component.common.core.validation.ValidationUtils;
import top.egon.cola.component.common.id.snowflake.SnowflakeIdGenerator;
import top.egon.cola.component.rpc.config.EgonRpcProperties;
import top.egon.cola.component.rpc.consumer.channel.RpcChannelKey;
import top.egon.cola.component.rpc.consumer.channel.RpcConsumerChannelFactory;
import top.egon.cola.component.rpc.consumer.channel.RpcConsumerChannelPool;
import top.egon.cola.component.rpc.consumer.invocation.RpcInvocationExecutor;
import top.egon.cola.component.rpc.consumer.proxy.EgonRpcReferenceBeanPostProcessor;
import top.egon.cola.component.rpc.consumer.proxy.RpcConsumerProxyFactory;
import top.egon.cola.component.rpc.consumer.reference.RpcReferenceDefinitionResolver;
import top.egon.cola.component.rpc.consumer.reference.RpcReferenceStrategyFactory;
import top.egon.cola.component.rpc.context.identity.RpcProcessIdentity;
import top.egon.cola.component.rpc.context.invocation.RpcMetadataKeys;
import top.egon.cola.component.rpc.contract.validation.RpcContractValidator;
import top.egon.cola.component.rpc.exception.RpcStatusExceptionMapper;
import top.egon.cola.platform.tianquan.jianshen.core.rule.Rbac3RuleViolation;
import top.egon.cola.platform.tianquan.shoubing.rpc.contract.proto.v1.GetTenantMembershipRequest;
import top.egon.cola.platform.tianquan.shoubing.rpc.contract.proto.v1.GetTenantMembershipResponse;
import top.egon.cola.platform.tianquan.shoubing.rpc.contract.proto.v1.IdentityDirectoryServiceGrpc;
import top.egon.cola.platform.tianquan.shoubing.rpc.contract.proto.v1.IdentityStatus;
import top.egon.cola.platform.tianquan.shoubing.rpc.contract.proto.v1.MembershipStatus;
import top.egon.cola.platform.tianquan.shoubing.rpc.contract.proto.v1.TenantMembershipProfile;
import top.egon.cola.platform.tianquan.shoubing.rpc.contract.proto.v1.TenantStatus;

import java.io.IOException;
import java.net.InetSocketAddress;
import java.net.SocketAddress;
import java.net.URI;
import java.time.Clock;
import java.time.Instant;
import java.time.ZoneOffset;
import java.util.Map;
import java.time.Duration;
import java.util.List;
import java.util.Set;
import java.util.concurrent.CopyOnWriteArrayList;
import java.util.concurrent.CountDownLatch;
import java.util.concurrent.TimeUnit;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.when;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.times;

@Timeout(15)
class IdentityDirectoryNativeTransportTest {

    private static final String BINDING = "shoubing-identity-directory";
    private static final String AUTHORITY = "tianquan-shoubing-rpc.permission-prod.svc.cluster.local:18122";
    private static final String ISSUER = "https://identity.example.test/tenant-a";
    private static final URI JIANSHEN_RESOURCE = URI.create("https://api.example.test/jianshen");
    private static final URI SHOUBING_RESOURCE = URI.create("https://api.example.test/shoubing");
    private static final String REGISTRATION = "jianshen-directory-tenant-17";
    private static final Instant NOW = Instant.now();
    private static final String MEMBERSHIP =
            IdentityDirectoryServiceGrpc.getGetTenantMembershipMethod().getFullMethodName();
    private static final String PROFILES =
            IdentityDirectoryServiceGrpc.getBatchGetIdentityProfilesMethod().getFullMethodName();

    @BeforeAll
    static void initializeCallIds() {
        SnowflakeIdGenerator.initialize(0L, Duration.ofMillis(5));
    }

    @Test
    void bothTypedConsumersShareOneH2cConnectionWithMethodSpecificRetry() throws Exception {
        WireProbe probe = new WireProbe();
        List<ManagedChannel> channels = new CopyOnWriteArrayList<>();
        EgonRpcProperties properties = configuredRpc(false);
        assertThat(properties.getTransport()).isEqualTo("h2c");
        assertThat(properties.getProvider().isEnabled()).isFalse();
        var approval = properties.getConsumer().getRetryApprovals().remove(MEMBERSHIP);
        assertThat(approval).isEqualTo(new EgonRpcProperties.RpcRetryApprovalConfig(1, 600, 1500));
        assertThat(properties.getConsumer().getRetryApprovals()).isEmpty();

        var oauth = mock(IdpServiceOAuth2Client.class);
        when(oauth.authorize(any())).thenReturn(new OAuth2AccessToken(OAuth2AccessToken.TokenType.BEARER,
                "directory-service-token", NOW, NOW.plusSeconds(300)));
        try (var caller = new AuthorizedUserScope();
             var runtime = new NativeRuntime(probe, channels);
             var validators = Validation.buildDefaultValidatorFactory();
             var executor = new RpcInvocationExecutor(new RpcStatusExceptionMapper());
             var pool = runtime.channelPool();
             var strategies = new RpcReferenceStrategyFactory(pool)) {
            var contractValidator = new RpcContractValidator(new ValidationUtils(validators.getValidator()));
            var idp = configuredCredentials();
            var credentialFactory = IdpRpcClientCredentialInterceptorFactory.createConfigured(oauth, idp,
                    validators.getValidator(), new Rbac3IdentityDirectoryTenantResolver(Clock.fixed(NOW, ZoneOffset.UTC)));
            credentialFactory.validateConfiguration();
            assertThat(idp.getRpc().getConsumer().getBindings()).containsOnlyKeys("tenant-membership", "identity-profiles");
            idp.getRpc().getConsumer().getBindings().values().forEach(binding -> {
                assertThat(binding.getMode()).isEqualTo(IdpStarterProperties.RpcConsumerModeEnum.SERVICE);
                assertThat(binding.getScopeContext()).isEqualTo(ServiceTokenContext.TENANT);
                assertThat(binding.getScopes()).containsExactly("identity:read");
                assertThat(binding.getResourceUri()).isEqualTo(SHOUBING_RESOURCE);
                assertThat(binding.getTenantRegistrationIds()).containsExactlyEntriesOf(Map.of("17", REGISTRATION));
            });
            var proxyFactory = new RpcConsumerProxyFactory(executor,
                    new RpcProcessIdentity("tianquan-jianshen-admin", "test", "127.0.0.1", 1, "jianshen-test"), List.of(credentialFactory));
            var membership = new IdentityTenantMembershipDirectory();
            var profiles = new IdentityProfileDirectory();

            var unapproved = new EgonRpcReferenceBeanPostProcessor(
                    contractValidator, new RpcReferenceDefinitionResolver(properties), strategies, proxyFactory);
            unapproved.postProcessBeforeInitialization(membership, "membership");
            assertThat(channels).hasSize(1);
            awaitReady(channels.getFirst());
            assertThatThrownBy(() -> membership.requireActive("17", "subject-17"))
                    .isInstanceOfSatisfying(Rbac3RuleViolation.class,
                            failure -> assertThat(failure.reasonCode())
                                    .isEqualTo("IDENTITY_TENANT_MEMBERSHIP_UNAVAILABLE"));
            assertThat(probe.arrivals).extracting(ArrivalVO::attempt).containsExactly("1");
            assertThat(probe.arrivals.getFirst().authorizations()).containsExactly("Bearer directory-service-token");
            probe.arrivals.clear();

            properties.getConsumer().getRetryApprovals().put(MEMBERSHIP, approval);
            var references = new EgonRpcReferenceBeanPostProcessor(
                    contractValidator, new RpcReferenceDefinitionResolver(properties), strategies, proxyFactory);
            references.postProcessBeforeInitialization(membership, "membership");
            references.postProcessBeforeInitialization(profiles, "profiles");
            assertThat(channels).hasSize(1);
            awaitReady(channels.getFirst());

            assertThat(membership.requireActive("17", "subject-17").membershipVersion()).isEqualTo(8);
            assertThat(profiles.batchGet(List.of("subject-17")).available()).isFalse();

            assertThat(probe.arrivals).extracting(ArrivalVO::method)
                    .containsExactly(MEMBERSHIP, MEMBERSHIP, PROFILES);
            assertThat(probe.arrivals).extracting(ArrivalVO::attempt).containsExactly("1", "2", "1");
            ArrivalVO first = probe.arrivals.getFirst();
            ArrivalVO retry = probe.arrivals.get(1);
            assertThat(first.callId()).isNotBlank().isEqualTo(retry.callId());
            assertThat(first.digest()).matches("[a-f0-9]{64}").isEqualTo(retry.digest());
            assertThat(probe.arrivals.getLast().callId()).isNotEqualTo(first.callId());
            assertThat(first.deadlineMs()).isBetween(1L, 600L);
            assertThat(retry.deadlineMs()).isBetween(1L, 600L);
            assertThat(probe.arrivals.getLast().deadlineMs()).isBetween(1L, 1500L);
            assertThat(probe.arrivals).extracting(ArrivalVO::remote).containsOnly(first.remote());
            assertThat(probe.arrivals).allSatisfy(arrival -> {
                assertThat(arrival.authority()).isEqualTo(AUTHORITY);
                assertThat(arrival.tls()).isFalse();
                assertThat(arrival.authorizations()).containsExactly("Bearer directory-service-token");
            });
            verify(oauth, times(4)).authorize(new IdpServiceTokenRequest(REGISTRATION, "jianshen-service-app", SHOUBING_RESOURCE,
                    ServiceTokenContext.TENANT, "17", Set.of("identity:read")));
        }
    }

    @Test
    void localProfileRetainsTheSameApprovedMethodsWithAnIsolatedNamespace() throws IOException {
        var properties = configuredRpc(true);
        var binding = properties.getConsumer().getBindings().get(BINDING);
        assertThat(properties.getTransport()).isEqualTo("h2c");
        assertThat(properties.getProvider().isEnabled()).isFalse();
        assertThat(binding.getNamespace()).isEqualTo("permission-local");
        assertThat(binding.getService()).isEqualTo("tianquan-shoubing-rpc");
        assertThat(binding.getPort()).isEqualTo(18122);
        assertThat(binding.getMethods()).isEqualTo(Set.of(MEMBERSHIP, PROFILES));
        assertThat(properties.getConsumer().getRetryApprovals()).containsOnlyKeys(MEMBERSHIP);
    }

    private static EgonRpcProperties configuredRpc(boolean local) throws IOException {
        return Binder.get(configuredEnvironment(local)).bind("egon.cola.component.rpc", EgonRpcProperties.class).get();
    }

    private static IdpStarterProperties configuredCredentials() throws IOException {
        var environment = configuredEnvironment(false)
                .withProperty("TIANQUAN_JIANSHEN_SERVICE_APP_ID", "jianshen-service-app")
                .withProperty("TIANQUAN_SHOUBING_RESOURCE_URI", SHOUBING_RESOURCE.toASCIIString());
        // Exact authorized deployment projection: no wildcard or default registration exists.
        for (String binding : List.of("tenant-membership", "identity-profiles")) {
            environment.withProperty("egon.cola.platform.tianquan.shoubing.rpc.consumer.bindings." + binding
                    + ".tenant-registration-ids[17]", REGISTRATION);
        }
        var properties = new IdpStarterProperties();
        properties.setRpc(Binder.get(environment).bind("egon.cola.platform.tianquan.shoubing.rpc", IdpStarterProperties.RpcProperties.class).get());
        return properties;
    }

    private static MockEnvironment configuredEnvironment(boolean local) throws IOException {
        var loader = new YamlPropertySourceLoader();
        var environment = new MockEnvironment()
                .withProperty("DEPLOYMENT_ENV", local ? "local" : "test")
                .withProperty("TIANQUAN_JIANSHEN_ADVERTISED_HOST", "127.0.0.1")
                .withProperty("TIANQUAN_JIANSHEN_INSTANCE_ID", "jianshen-test");
        loader.load("main", new ClassPathResource("application.yml"))
                .forEach(source -> environment.getPropertySources().addLast(source));
        if (local) {
            loader.load("local", new ClassPathResource("application-local.yml"))
                    .forEach(source -> environment.getPropertySources().addFirst(source));
        }
        return environment;
    }

    private static void awaitReady(ManagedChannel channel) throws InterruptedException {
        long deadline = System.nanoTime() + TimeUnit.SECONDS.toNanos(5);
        while (true) {
            ConnectivityState state = channel.getState(true);
            if (state == ConnectivityState.READY) {
                return;
            }
            var changed = new CountDownLatch(1);
            channel.notifyWhenStateChanged(state, changed::countDown);
            assertThat(changed.await(Math.max(0, deadline - System.nanoTime()), TimeUnit.NANOSECONDS))
                    .isTrue();
        }
    }

    /** Trusted local authentication fixture; no synthetic JWT or IdP authentication is installed. */
    private static final class AuthorizedUserScope implements AutoCloseable {
        private final SecurityContext previousSecurity = SecurityContextHolder.getContext();
        private final TenantContext previousTenant = TenantContext.currentOrNull();

        private AuthorizedUserScope() {
            var identity = new IdentityPrincipal("user-17", "17", "verified-fixture-token", Set.of(JIANSHEN_RESOURCE.toASCIIString()),
                    NOW.minusSeconds(1), NOW.plusSeconds(300), AuthenticationContext.of("PASSWORD", NOW.minusSeconds(1)));
            var snapshot = new SystemAuthorizationSnapshot("17", "user-17", "rbac-user-17", "tianquan-jianshen-admin",
                    1L, 1L, List.of(), Set.of("system:user:manage"), Map.of(), Map.of(), "sha256:fixture", NOW, NOW.plusSeconds(300));
            var authentication = new Rbac3AuthenticationToken(new Rbac3UserDetails(identity, snapshot));
            authentication.setDetails(new TokenAuditProofBO(URI.create(ISSUER), JIANSHEN_RESOURCE, null, null, null));
            var security = SecurityContextHolder.createEmptyContext();
            security.setAuthentication(authentication);
            SecurityContextHolder.setContext(security);
            TenantContext.set(new TenantContext("17", "17", false));
        }

        @Override public void close() {
            SecurityContextHolder.setContext(previousSecurity);
            if (previousTenant == null) { TenantContext.clear(); } else { TenantContext.set(previousTenant); }
        }
    }

    private static final class NativeRuntime implements AutoCloseable {
        private final Server server;
        private final List<ManagedChannel> channels;

        private NativeRuntime(WireProbe probe, List<ManagedChannel> channels) throws Exception {
            this.channels = channels;
            server = NettyServerBuilder.forAddress(new InetSocketAddress("127.0.0.1", 0))
                    .addService(new MembershipFixture()).intercept(probe).build().start();
        }

        private RpcConsumerChannelPool channelPool() {
            var factory = new RpcConsumerChannelFactory(4 * 1024 * 1024, 1000) {
                @Override
                public ManagedChannel create(RpcChannelKey key) {
                    assertThat(key.dnsTarget()).isEqualTo("dns:///" + AUTHORITY);
                    ManagedChannel channel = NettyChannelBuilder.forAddress("127.0.0.1", server.getPort())
                            .overrideAuthority(AUTHORITY).usePlaintext()
                            .disableServiceConfigLookUp().disableRetry().build();
                    channels.add(channel);
                    return channel;
                }
            };
            return new RpcConsumerChannelPool(factory, Duration.ofSeconds(1));
        }

        @Override
        public void close() throws InterruptedException {
            server.shutdownNow().awaitTermination(5, TimeUnit.SECONDS);
        }
    }

    private record ArrivalVO(String method, String attempt, String callId, String digest, long deadlineMs,
                             String authority, SocketAddress remote, boolean tls, List<String> authorizations) {
    }

    private static final class WireProbe implements ServerInterceptor {
        private final List<ArrivalVO> arrivals = new CopyOnWriteArrayList<>();

        private static List<String> authorizations(Metadata headers) {
            var values = headers.getAll(RpcMetadataKeys.AUTHORIZATION);
            return values == null ? List.of() : java.util.stream.StreamSupport.stream(values.spliterator(), false).toList();
        }

        @Override
        public <ReqT, RespT> ServerCall.Listener<ReqT> interceptCall(ServerCall<ReqT, RespT> call,
                Metadata headers, ServerCallHandler<ReqT, RespT> next) {
            String method = call.getMethodDescriptor().getFullMethodName();
            String attempt = headers.get(RpcMetadataKeys.ATTEMPT);
            var deadline = Context.current().getDeadline();
            arrivals.add(new ArrivalVO(method, attempt, headers.get(RpcMetadataKeys.LOGICAL_CALL_ID),
                    headers.get(RpcMetadataKeys.REQUEST_DIGEST),
                    deadline == null ? -1 : deadline.timeRemaining(TimeUnit.MILLISECONDS),
                    call.getAuthority(), call.getAttributes().get(Grpc.TRANSPORT_ATTR_REMOTE_ADDR),
                    call.getAttributes().get(Grpc.TRANSPORT_ATTR_SSL_SESSION) != null, authorizations(headers)));
            if (!authorizations(headers).equals(List.of("Bearer directory-service-token"))) {
                call.close(Status.UNAUTHENTICATED.withDescription("fixture SERVICE bearer required"), new Metadata());
                return new ServerCall.Listener<>() { };
            }
            if (PROFILES.equals(method) || "1".equals(attempt)) {
                call.close(Status.UNAVAILABLE.withDescription("fixture upstream unavailable"), new Metadata());
                return new ServerCall.Listener<>() { };
            }
            return next.startCall(call, headers);
        }
    }

    private static final class MembershipFixture extends IdentityDirectoryServiceGrpc.IdentityDirectoryServiceImplBase {
        @Override
        public void getTenantMembership(GetTenantMembershipRequest request,
                StreamObserver<GetTenantMembershipResponse> response) {
            response.onNext(GetTenantMembershipResponse.newBuilder()
                    .setProfile(TenantMembershipProfile.newBuilder()
                            .setTenantId(request.getTenantId()).setIdentitySub(request.getIdentitySub())
                            .setTenantStatus(TenantStatus.TENANT_STATUS_ACTIVE)
                            .setIdentityStatus(IdentityStatus.IDENTITY_STATUS_ACTIVE)
                            .setMembershipStatus(MembershipStatus.MEMBERSHIP_STATUS_ACTIVE)
                            .setMembershipVersion(8))
                    .build());
            response.onCompleted();
        }
    }
}
