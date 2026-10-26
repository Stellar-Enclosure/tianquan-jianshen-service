package top.egon.cola.platform.tianquan.jianshen.admin.registration.catalog.repository;

import top.egon.cola.platform.tianquan.jianshen.admin.registration.catalog.domain.vo.DeploymentQualificationReceiptVO;
import jakarta.persistence.EntityManager;
import org.springframework.stereotype.Repository;
import org.springframework.transaction.annotation.Propagation;
import org.springframework.transaction.annotation.Transactional;
import top.egon.cola.platform.tianquan.jianshen.admin.registration.catalog.domain.PermissionCatalogCaller;
import top.egon.cola.platform.tianquan.jianshen.admin.registration.catalog.domain.convertor.PermissionCatalogJson;
import top.egon.cola.platform.tianquan.jianshen.contract.permission.CatalogScope;
import top.egon.cola.platform.tianquan.jianshen.contract.permission.DeploymentQualificationRequest;
import top.egon.cola.platform.tianquan.jianshen.core.rule.Rbac3RuleViolation;

import java.time.Instant;
import java.util.Optional;

/** Immutable attestations retain the verified authority; activation rechecks that authority's current grant. */
@Repository
@Transactional(propagation = Propagation.MANDATORY)
public class DeploymentQualificationRepository {

    private final EntityManager entityManager;
    private final PermissionCatalogJson json;

    public DeploymentQualificationRepository(EntityManager entityManager, PermissionCatalogJson json) {
        this.entityManager = entityManager;
        this.json = json;
    }

    public Optional<DeploymentQualificationReceiptVO> findCurrent(CatalogScope scope, String producer, String digest, PermissionCatalogCaller caller, Instant now) {
        var rows = entityManager.createNativeQuery("""
                select original_receipt_json::text from rbac3_catalog_deployment_qualification
                 where catalog_scope_id=:scope and producer_id=:producer
                   and original_receipt_json->>'requestDigest'=:digest and trusted_issuer=:issuer
                   and trusted_client_id=:client and trusted_resource=:resource and expires_at>:now
                 order by verified_at desc, id desc limit 1
                """).setParameter("scope", Long.parseLong(scope.catalogScopeId())).setParameter("producer", producer)
                .setParameter("digest", digest).setParameter("issuer", caller.issuer().toString())
                .setParameter("client", caller.principal().clientId()).setParameter("resource", caller.principal().resourceUri().toString())
                .setParameter("now", now).getResultList();
        return rows.isEmpty() ? Optional.empty() : Optional.of(json.read(rows.getFirst().toString(), DeploymentQualificationReceiptVO.class));
    }

    public void save(DeploymentQualificationReceiptVO receipt) {
        var request = receipt.attestation();
        entityManager.createNativeQuery("""
                insert into rbac3_catalog_deployment_qualification
                    (id,catalog_scope_id,producer_id,producer_version,artifact_digest,manifest_digest,policy_digest,
                     pipeline_id,build_id,source_ref,commit,deployment_id,readiness_digest,trusted_issuer,trusted_client_id,
                     trusted_resource,verified_at,expires_at,original_receipt_json)
                values (:id,:scope,:producer,:revision,:artifact,:manifest,:policy,:pipeline,:build,:sourceRef,:commit,
                        :deployment,:readiness,:issuer,:client,:resource,:verifiedAt,:expiresAt,cast(:receipt as jsonb))
                """).setParameter("id", Long.parseLong(receipt.qualificationId())).setParameter("scope", Long.parseLong(request.target().catalogScopeId()))
                .setParameter("producer", request.producerId()).setParameter("revision", Long.parseLong(request.producerVersion()))
                .setParameter("artifact", request.artifactDigest()).setParameter("manifest", request.manifestDigest()).setParameter("policy", request.policyDigest())
                .setParameter("pipeline", request.pipelineId()).setParameter("build", request.buildId()).setParameter("sourceRef", request.sourceRef())
                .setParameter("commit", request.commit()).setParameter("deployment", request.deploymentId()).setParameter("readiness", request.readiness().digest())
                .setParameter("issuer", receipt.issuer()).setParameter("client", receipt.clientId()).setParameter("resource", receipt.resourceUri())
                .setParameter("verifiedAt", receipt.verifiedAt()).setParameter("expiresAt", receipt.expiresAt())
                .setParameter("receipt", json.write(receipt)).executeUpdate();
    }

    public DeploymentQualificationReceiptVO requireTrusted(CatalogScope scope, String producer, long revision, long id, Instant now) {
        var rows = entityManager.createNativeQuery("""
                select q.original_receipt_json::text from rbac3_catalog_deployment_qualification q
                  join rbac3_catalog_service_grant g on g.catalog_scope_id=q.catalog_scope_id and g.producer_id=q.producer_id
                   and g.issuer=q.trusted_issuer and g.client_id=q.trusted_client_id and g.resource_uri=q.trusted_resource
                 where q.catalog_scope_id=:scope and q.producer_id=:producer and q.producer_version=:revision and q.id=:id
                   and q.verified_at<=:now and q.expires_at>:now and g.enabled
                   and g.capabilities @> '["QUALIFY_DEPLOYMENT"]'::jsonb
                   and g.allowed_source_refs @> jsonb_build_array(q.source_ref)
                 for share of g
                """).setParameter("scope", Long.parseLong(scope.catalogScopeId())).setParameter("producer", producer)
                .setParameter("revision", revision).setParameter("id", id).setParameter("now", now).getResultList();
        if (rows.size() != 1) throw new Rbac3RuleViolation("SERVICE_IDENTITY_DENIED");
        DeploymentQualificationReceiptVO receipt = json.read(rows.getFirst().toString(), DeploymentQualificationReceiptVO.class);
        if (!scope.equals(receipt.attestation().target()) || !producer.equals(receipt.attestation().producerId())
                || !Long.toString(revision).equals(receipt.attestation().producerVersion()) || !Long.toString(id).equals(receipt.qualificationId())) {
            throw new Rbac3RuleViolation("RESOURCE_MANIFEST_CONFLICT");
        }
        return receipt;
    }
}
