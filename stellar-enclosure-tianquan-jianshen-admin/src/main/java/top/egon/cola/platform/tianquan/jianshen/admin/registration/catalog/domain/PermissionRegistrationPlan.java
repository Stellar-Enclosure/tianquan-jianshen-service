package top.egon.cola.platform.tianquan.jianshen.admin.registration.catalog.domain;

import top.egon.cola.platform.tianquan.jianshen.contract.permission.ManifestDigests;
import top.egon.cola.platform.tianquan.jianshen.contract.permission.ManifestRegistrationRequest;
import top.egon.cola.platform.tianquan.jianshen.core.registration.PermissionManifestDiff;

import java.time.Instant;

/** Frozen local plan evidence; all authority versions are checked again when applied. */
public record PermissionRegistrationPlan(long id, ManifestRegistrationRequest.Plan request, long ownerVersion,
                                         long serviceGrantId, long serviceGrantVersion, ManifestDigests digests,
                                         PermissionManifestDiff.Result diff, Instant expiresAt, Instant createdAt,
                                         String createdBy) { }
