-- Permission-as-code catalog, activation and PostgreSQL runtime authority.
-- JSONB storage ceilings allow PostgreSQL spacing; shared contract validation enforces canonical byte limits.
-- B14/V15 are immutable. Legacy grants remain historical and are not converted.
-- The clean-environment precondition avoids inventing a scope for existing data rules.
DO $body$
BEGIN
    IF EXISTS (SELECT 1 FROM rbac3_data_rule) THEN
        RAISE EXCEPTION 'RBAC_PERMISSION_CATALOG_REQUIRES_EMPTY_LEGACY_DATA_RULES' USING ERRCODE = '55000';
    END IF;
END;
$body$;

CREATE TABLE rbac3_catalog_scope (
    id bigint NOT NULL CHECK (id > 0),
    tenant_id bigint NOT NULL CHECK (tenant_id > 0),
    business_code varchar(128) NOT NULL CHECK (business_code ~ '^[A-Za-z0-9][A-Za-z0-9._:/-]*$'),
    application_id bigint NOT NULL CHECK (application_id > 0),
    application_code varchar(128) NOT NULL CHECK (application_code ~ '^[A-Za-z0-9][A-Za-z0-9._:/-]*$'),
    namespace_code varchar(128) NOT NULL CHECK (namespace_code ~ '^[A-Za-z0-9][A-Za-z0-9._:/-]*$'),
    environment varchar(32) NOT NULL CHECK (environment ~ '^[A-Za-z0-9][A-Za-z0-9._:/-]*$'),
    ddc_business_id varchar(64) NOT NULL,
    ddc_application_id varchar(64) NOT NULL,
    status varchar(32) NOT NULL DEFAULT 'DISABLED' CHECK (status IN ('ACTIVE','DISABLED')),
    version bigint NOT NULL DEFAULT 0 CHECK (version >= 0),
    created_at timestamptz NOT NULL,
    created_by varchar(128) NOT NULL,
    updated_at timestamptz NOT NULL,
    updated_by varchar(128) NOT NULL,
    PRIMARY KEY (id),
    UNIQUE (tenant_id, business_code, application_code, namespace_code, environment),
    UNIQUE (id, tenant_id, application_id),
    UNIQUE (id, tenant_id),
    FOREIGN KEY (tenant_id) REFERENCES rbac3_tenant_authorization_state (tenant_id),
    FOREIGN KEY (application_id, application_code) REFERENCES rbac3_application (id, application_code)
);

CREATE UNIQUE INDEX uq_catalog_scope_case ON rbac3_catalog_scope (tenant_id, lower(business_code), lower(application_code), lower(namespace_code), lower(environment));

CREATE TABLE rbac3_catalog_producer (
    catalog_scope_id bigint NOT NULL CHECK (catalog_scope_id > 0),
    producer_id varchar(128) NOT NULL CHECK (producer_id ~ '^[A-Za-z0-9][A-Za-z0-9._:/-]*$'),
    kind varchar(32) NOT NULL CHECK (kind IN ('JAVA','REACT_TYPESCRIPT')),
    owned_key_prefixes jsonb NOT NULL CHECK (jsonb_typeof(owned_key_prefixes) = 'array' AND octet_length(owned_key_prefixes::text) <= 131072),
    owned_permission_prefixes jsonb NOT NULL CHECK (jsonb_typeof(owned_permission_prefixes) = 'array' AND octet_length(owned_permission_prefixes::text) <= 131072),
    owned_message_prefixes jsonb NOT NULL CHECK (jsonb_typeof(owned_message_prefixes) = 'array' AND octet_length(owned_message_prefixes::text) <= 131072),
    expected_modules jsonb NOT NULL CHECK (jsonb_typeof(expected_modules) = 'array' AND octet_length(expected_modules::text) <= 131072),
    current_revision bigint NOT NULL DEFAULT 0 CHECK (current_revision >= 0),
    enabled boolean NOT NULL DEFAULT false,
    version bigint NOT NULL DEFAULT 0 CHECK (version >= 0),
    created_at timestamptz NOT NULL,
    created_by varchar(128) NOT NULL,
    updated_at timestamptz NOT NULL,
    updated_by varchar(128) NOT NULL,
    PRIMARY KEY (catalog_scope_id, producer_id),
    FOREIGN KEY (catalog_scope_id) REFERENCES rbac3_catalog_scope (id),
    CHECK (jsonb_array_length(expected_modules) BETWEEN 1 AND 256),
    CHECK (jsonb_array_length(owned_key_prefixes) <= 128 AND jsonb_array_length(owned_permission_prefixes) <= 128 AND jsonb_array_length(owned_message_prefixes) <= 128)
);

CREATE UNIQUE INDEX uq_catalog_producer_case ON rbac3_catalog_producer (catalog_scope_id, lower(producer_id));

CREATE TABLE rbac3_catalog_service_grant (
    id bigint NOT NULL CHECK (id > 0),
    catalog_scope_id bigint NOT NULL CHECK (catalog_scope_id > 0),
    producer_id varchar(128) NOT NULL CHECK (producer_id ~ '^[A-Za-z0-9][A-Za-z0-9._:/-]*$'),
    issuer varchar(2048) NOT NULL,
    client_id varchar(200) NOT NULL,
    resource_uri varchar(2048) NOT NULL,
    principal_binding_digest char(64) NOT NULL CHECK (principal_binding_digest ~ '^[0-9a-f]{64}$'),
    capabilities jsonb NOT NULL CHECK (jsonb_typeof(capabilities) = 'array' AND octet_length(capabilities::text) <= 16384),
    allowed_source_refs jsonb NOT NULL CHECK (jsonb_typeof(allowed_source_refs) = 'array' AND octet_length(allowed_source_refs::text) <= 131072),
    allow_permission_expansion boolean NOT NULL DEFAULT false,
    enabled boolean NOT NULL DEFAULT false,
    version bigint NOT NULL DEFAULT 0 CHECK (version >= 0),
    created_at timestamptz NOT NULL,
    created_by varchar(128) NOT NULL,
    updated_at timestamptz NOT NULL,
    updated_by varchar(128) NOT NULL,
    PRIMARY KEY (id),
    UNIQUE (catalog_scope_id, producer_id, principal_binding_digest),
    UNIQUE (catalog_scope_id, producer_id, id),
    FOREIGN KEY (catalog_scope_id, producer_id) REFERENCES rbac3_catalog_producer (catalog_scope_id, producer_id),
    CHECK (capabilities <@ '["REGISTER","ACTIVATE","READ_DESCRIPTOR","QUALIFY_DEPLOYMENT","CLEAR_PRODUCER"]'::jsonb),
    CHECK (length(issuer)>0 AND length(client_id)>0 AND length(resource_uri)>0)
);

CREATE TABLE rbac3_catalog_resource (
    id bigint NOT NULL CHECK (id > 0),
    catalog_scope_id bigint NOT NULL CHECK (catalog_scope_id > 0),
    registration_key varchar(200) NOT NULL CHECK (registration_key ~ '^[A-Za-z0-9][A-Za-z0-9._:/-]*$'),
    owner_producer_id varchar(128) NOT NULL CHECK (owner_producer_id ~ '^[A-Za-z0-9][A-Za-z0-9._:/-]*$'),
    resource_type varchar(32) NOT NULL CHECK (resource_type IN ('APP','MENU','PAGE','COMPONENT','BUTTON','API','FIELD')),
    governance_state varchar(32) NOT NULL DEFAULT 'ACTIVE' CHECK (governance_state IN ('ACTIVE','DISABLED','RETIRED')),
    version bigint NOT NULL DEFAULT 0 CHECK (version >= 0),
    created_at timestamptz NOT NULL,
    created_by varchar(128) NOT NULL,
    updated_at timestamptz NOT NULL,
    updated_by varchar(128) NOT NULL,
    PRIMARY KEY (id),
    UNIQUE (catalog_scope_id, registration_key),
    UNIQUE (catalog_scope_id, id),
    FOREIGN KEY (catalog_scope_id, owner_producer_id) REFERENCES rbac3_catalog_producer (catalog_scope_id, producer_id)
);

CREATE UNIQUE INDEX uq_catalog_resource_case ON rbac3_catalog_resource (catalog_scope_id, lower(registration_key));

CREATE TABLE rbac3_catalog_permission (
    id bigint NOT NULL CHECK (id > 0),
    catalog_scope_id bigint NOT NULL CHECK (catalog_scope_id > 0),
    permission_code varchar(128) NOT NULL CHECK (permission_code ~ '^[A-Za-z0-9][A-Za-z0-9._:/-]*$'),
    owner_producer_id varchar(128) NOT NULL CHECK (owner_producer_id ~ '^[A-Za-z0-9][A-Za-z0-9._:/-]*$'),
    meaning varchar(1024) NOT NULL CHECK (length(meaning)>0),
    governance_state varchar(32) NOT NULL DEFAULT 'ACTIVE' CHECK (governance_state IN ('ACTIVE','DISABLED','RETIRED')),
    version bigint NOT NULL DEFAULT 0 CHECK (version >= 0),
    created_at timestamptz NOT NULL,
    created_by varchar(128) NOT NULL,
    updated_at timestamptz NOT NULL,
    updated_by varchar(128) NOT NULL,
    PRIMARY KEY (id),
    UNIQUE (catalog_scope_id, permission_code),
    UNIQUE (catalog_scope_id, id),
    FOREIGN KEY (catalog_scope_id, owner_producer_id) REFERENCES rbac3_catalog_producer (catalog_scope_id, producer_id)
);

CREATE UNIQUE INDEX uq_catalog_permission_case ON rbac3_catalog_permission (catalog_scope_id, lower(permission_code));

CREATE TABLE rbac3_catalog_manifest (
    catalog_scope_id bigint NOT NULL CHECK (catalog_scope_id > 0),
    producer_id varchar(128) NOT NULL CHECK (producer_id ~ '^[A-Za-z0-9][A-Za-z0-9._:/-]*$'),
    producer_version bigint NOT NULL CHECK (producer_version > 0),
    manifest_digest char(64) NOT NULL CHECK (manifest_digest ~ '^[0-9a-f]{64}$'),
    policy_digest char(64) NOT NULL CHECK (policy_digest ~ '^[0-9a-f]{64}$'),
    metadata_digest char(64) NOT NULL CHECK (metadata_digest ~ '^[0-9a-f]{64}$'),
    canonical_manifest jsonb NOT NULL CHECK (jsonb_typeof(canonical_manifest) = 'object' AND octet_length(canonical_manifest::text) <= 33554432),
    state varchar(32) NOT NULL DEFAULT 'REGISTERED' CHECK (state IN ('REGISTERED','METADATA_PENDING','READY','FAILED')),
    source_operation_id varchar(36) NOT NULL CHECK (source_operation_id ~ '^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$'),
    repository varchar(256) NOT NULL,
    commit varchar(64) NOT NULL CHECK (commit ~ '^([0-9a-f]{40}|[0-9a-f]{64})$'),
    build_id varchar(256) NOT NULL,
    artifact_version varchar(128) NOT NULL,
    resource_count integer NOT NULL CHECK (resource_count BETWEEN 0 AND 10000),
    permission_count integer NOT NULL CHECK (permission_count BETWEEN 0 AND 10000),
    message_count integer NOT NULL CHECK (message_count BETWEEN 0 AND 20000),
    diff_json jsonb NOT NULL CHECK (jsonb_typeof(diff_json) = 'object' AND octet_length(diff_json::text) <= 33554432),
    metadata_receipt_id varchar(128),
    failure_code varchar(128),
    version bigint NOT NULL DEFAULT 0 CHECK (version >= 0),
    created_at timestamptz NOT NULL,
    created_by varchar(128) NOT NULL,
    updated_at timestamptz NOT NULL,
    PRIMARY KEY (catalog_scope_id, producer_id, producer_version),
    UNIQUE (catalog_scope_id, producer_id, manifest_digest),
    FOREIGN KEY (catalog_scope_id, producer_id) REFERENCES rbac3_catalog_producer (catalog_scope_id, producer_id),
    CHECK ((state = 'READY') = (metadata_receipt_id IS NOT NULL)),
    CHECK ((state = 'FAILED') = (failure_code IS NOT NULL))
);

CREATE TABLE rbac3_catalog_resource_version (
    catalog_scope_id bigint NOT NULL CHECK (catalog_scope_id > 0),
    producer_id varchar(128) NOT NULL CHECK (producer_id ~ '^[A-Za-z0-9][A-Za-z0-9._:/-]*$'),
    producer_version bigint NOT NULL CHECK (producer_version > 0),
    resource_id bigint NOT NULL CHECK (resource_id > 0),
    registration_key varchar(200) NOT NULL CHECK (registration_key ~ '^[A-Za-z0-9][A-Za-z0-9._:/-]*$'),
    resource_type varchar(32) NOT NULL CHECK (resource_type IN ('APP','MENU','PAGE','COMPONENT','BUTTON','API','FIELD')),
    definition_lifecycle varchar(32) NOT NULL CHECK (definition_lifecycle IN ('ACTIVE','DEPRECATED')),
    classification varchar(32) NOT NULL CHECK (classification IN ('PUBLIC','INTERNAL','PROTECTED')),
    definition_json jsonb NOT NULL CHECK (jsonb_typeof(definition_json) = 'object' AND octet_length(definition_json::text) <= 524288),
    definition_digest char(64) NOT NULL CHECK (definition_digest ~ '^[0-9a-f]{64}$'),
    target_json jsonb NOT NULL CHECK (jsonb_typeof(target_json) = 'object' AND octet_length(target_json::text) <= 131072),
    i18n_json jsonb NOT NULL CHECK (jsonb_typeof(i18n_json) = 'object' AND octet_length(i18n_json::text) <= 65536),
    PRIMARY KEY (catalog_scope_id, producer_id, producer_version, resource_id),
    UNIQUE (catalog_scope_id, producer_id, producer_version, registration_key),
    FOREIGN KEY (catalog_scope_id, producer_id, producer_version) REFERENCES rbac3_catalog_manifest (catalog_scope_id, producer_id, producer_version),
    FOREIGN KEY (catalog_scope_id, resource_id) REFERENCES rbac3_catalog_resource (catalog_scope_id, id)
);

CREATE INDEX ix_catalog_resource_history ON rbac3_catalog_resource_version (catalog_scope_id, resource_id, producer_version);

CREATE TABLE rbac3_catalog_resource_requirement (
    catalog_scope_id bigint NOT NULL CHECK (catalog_scope_id > 0),
    producer_id varchar(128) NOT NULL CHECK (producer_id ~ '^[A-Za-z0-9][A-Za-z0-9._:/-]*$'),
    producer_version bigint NOT NULL CHECK (producer_version > 0),
    resource_id bigint NOT NULL CHECK (resource_id > 0),
    operation varchar(32) NOT NULL CHECK (operation IN ('ACCESS','PLAIN_READ','MASKED_READ','WRITE')),
    group_index smallint NOT NULL CHECK (group_index BETWEEN 0 AND 31),
    group_mode varchar(32) NOT NULL CHECK (group_mode IN ('ALL','ANY')),
    permission_code varchar(128) NOT NULL CHECK (permission_code ~ '^[A-Za-z0-9][A-Za-z0-9._:/-]*$'),
    permission_id bigint CHECK (permission_id > 0),
    code_index smallint NOT NULL CHECK (code_index BETWEEN 0 AND 63),
    PRIMARY KEY (catalog_scope_id, producer_id, producer_version, resource_id, operation, group_index, permission_code),
    UNIQUE (catalog_scope_id, producer_id, producer_version, resource_id, operation, group_index, code_index),
    FOREIGN KEY (catalog_scope_id, producer_id, producer_version, resource_id) REFERENCES rbac3_catalog_resource_version (catalog_scope_id, producer_id, producer_version, resource_id),
    FOREIGN KEY (catalog_scope_id, permission_id) REFERENCES rbac3_catalog_permission (catalog_scope_id, id)
);

CREATE TABLE rbac3_catalog_permission_version (
    catalog_scope_id bigint NOT NULL CHECK (catalog_scope_id > 0),
    producer_id varchar(128) NOT NULL CHECK (producer_id ~ '^[A-Za-z0-9][A-Za-z0-9._:/-]*$'),
    producer_version bigint NOT NULL CHECK (producer_version > 0),
    permission_id bigint NOT NULL CHECK (permission_id > 0),
    permission_code varchar(128) NOT NULL CHECK (permission_code ~ '^[A-Za-z0-9][A-Za-z0-9._:/-]*$'),
    definition_json jsonb NOT NULL CHECK (jsonb_typeof(definition_json) = 'object' AND octet_length(definition_json::text) <= 524288),
    definition_digest char(64) NOT NULL CHECK (definition_digest ~ '^[0-9a-f]{64}$'),
    i18n_json jsonb NOT NULL CHECK (jsonb_typeof(i18n_json) = 'object' AND octet_length(i18n_json::text) <= 65536),
    lifecycle varchar(32) NOT NULL CHECK (lifecycle IN ('ACTIVE','DEPRECATED')),
    PRIMARY KEY (catalog_scope_id, producer_id, producer_version, permission_id),
    UNIQUE (catalog_scope_id, producer_id, producer_version, permission_code),
    FOREIGN KEY (catalog_scope_id, producer_id, producer_version) REFERENCES rbac3_catalog_manifest (catalog_scope_id, producer_id, producer_version),
    FOREIGN KEY (catalog_scope_id, permission_id) REFERENCES rbac3_catalog_permission (catalog_scope_id, id)
);

CREATE TABLE rbac3_catalog_message_owner (
    catalog_scope_id bigint NOT NULL CHECK (catalog_scope_id > 0),
    page_code varchar(128) NOT NULL CHECK (page_code ~ '^[A-Za-z0-9][A-Za-z0-9._:/-]*$'),
    message_key varchar(128) NOT NULL CHECK (message_key ~ '^[A-Za-z0-9][A-Za-z0-9._:/-]*$'),
    owner_producer_id varchar(128) NOT NULL CHECK (owner_producer_id ~ '^[A-Za-z0-9][A-Za-z0-9._:/-]*$'),
    lifecycle varchar(32) NOT NULL DEFAULT 'ACTIVE' CHECK (lifecycle IN ('ACTIVE','DISABLED','RETIRED')),
    version bigint NOT NULL DEFAULT 0 CHECK (version >= 0),
    created_at timestamptz NOT NULL,
    created_by varchar(128) NOT NULL,
    updated_at timestamptz NOT NULL,
    updated_by varchar(128) NOT NULL,
    PRIMARY KEY (catalog_scope_id, page_code, message_key),
    FOREIGN KEY (catalog_scope_id, owner_producer_id) REFERENCES rbac3_catalog_producer (catalog_scope_id, producer_id)
);

CREATE UNIQUE INDEX uq_catalog_message_case ON rbac3_catalog_message_owner (catalog_scope_id, lower(page_code), lower(message_key));

CREATE TABLE rbac3_catalog_registration_plan (
    id bigint NOT NULL CHECK (id > 0),
    catalog_scope_id bigint NOT NULL CHECK (catalog_scope_id > 0),
    producer_id varchar(128) NOT NULL CHECK (producer_id ~ '^[A-Za-z0-9][A-Za-z0-9._:/-]*$'),
    expected_producer_revision bigint NOT NULL DEFAULT 0 CHECK (expected_producer_revision >= 0),
    expected_active_revision bigint NOT NULL DEFAULT 0 CHECK (expected_active_revision >= 0),
    owner_version bigint NOT NULL DEFAULT 0 CHECK (owner_version >= 0),
    service_grant_id bigint NOT NULL CHECK (service_grant_id > 0),
    service_grant_version bigint NOT NULL DEFAULT 0 CHECK (service_grant_version >= 0),
    manifest_digest char(64) NOT NULL CHECK (manifest_digest ~ '^[0-9a-f]{64}$'),
    policy_digest char(64) NOT NULL CHECK (policy_digest ~ '^[0-9a-f]{64}$'),
    metadata_digest char(64) NOT NULL CHECK (metadata_digest ~ '^[0-9a-f]{64}$'),
    request_digest char(64) NOT NULL CHECK (request_digest ~ '^[0-9a-f]{64}$'),
    canonical_manifest jsonb NOT NULL CHECK (jsonb_typeof(canonical_manifest) = 'object' AND octet_length(canonical_manifest::text) <= 33554432),
    diff_json jsonb NOT NULL CHECK (jsonb_typeof(diff_json) = 'object' AND octet_length(diff_json::text) <= 33554432),
    authorization_expansion boolean NOT NULL,
    expires_at timestamptz NOT NULL,
    created_at timestamptz NOT NULL,
    created_by varchar(128) NOT NULL,
    PRIMARY KEY (id),
    UNIQUE (catalog_scope_id, producer_id, id),
    FOREIGN KEY (catalog_scope_id, producer_id) REFERENCES rbac3_catalog_producer (catalog_scope_id, producer_id),
    FOREIGN KEY (catalog_scope_id, producer_id, service_grant_id) REFERENCES rbac3_catalog_service_grant (catalog_scope_id, producer_id, id),
    CHECK (expires_at > created_at)
);

CREATE INDEX ix_catalog_plan_expiry ON rbac3_catalog_registration_plan (expires_at);

CREATE TABLE rbac3_catalog_registration_operation (
    catalog_scope_id bigint NOT NULL CHECK (catalog_scope_id > 0),
    producer_id varchar(128) NOT NULL CHECK (producer_id ~ '^[A-Za-z0-9][A-Za-z0-9._:/-]*$'),
    operation_id varchar(36) NOT NULL CHECK (operation_id ~ '^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$'),
    plan_id bigint NOT NULL CHECK (plan_id > 0),
    request_digest char(64) NOT NULL CHECK (request_digest ~ '^[0-9a-f]{64}$'),
    manifest_digest char(64) NOT NULL CHECK (manifest_digest ~ '^[0-9a-f]{64}$'),
    producer_version bigint NOT NULL CHECK (producer_version > 0),
    original_receipt_json jsonb NOT NULL CHECK (jsonb_typeof(original_receipt_json) = 'object' AND octet_length(original_receipt_json::text) <= 33554432),
    created_at timestamptz NOT NULL,
    created_by varchar(128) NOT NULL,
    PRIMARY KEY (catalog_scope_id, producer_id, operation_id),
    FOREIGN KEY (catalog_scope_id, producer_id, plan_id) REFERENCES rbac3_catalog_registration_plan (catalog_scope_id, producer_id, id),
    FOREIGN KEY (catalog_scope_id, producer_id, producer_version) REFERENCES rbac3_catalog_manifest (catalog_scope_id, producer_id, producer_version)
);

CREATE TABLE rbac3_catalog_source_receipt (
    catalog_scope_id bigint NOT NULL CHECK (catalog_scope_id > 0),
    producer_id varchar(128) NOT NULL CHECK (producer_id ~ '^[A-Za-z0-9][A-Za-z0-9._:/-]*$'),
    producer_version bigint NOT NULL CHECK (producer_version > 0),
    source_operation_id varchar(36) NOT NULL CHECK (source_operation_id ~ '^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$'),
    receipt_id varchar(128) NOT NULL,
    source_version char(64) NOT NULL CHECK (source_version ~ '^[0-9a-f]{64}$'),
    manifest_digest char(64) NOT NULL CHECK (manifest_digest ~ '^[0-9a-f]{64}$'),
    policy_digest char(64) NOT NULL CHECK (policy_digest ~ '^[0-9a-f]{64}$'),
    metadata_digest char(64) NOT NULL CHECK (metadata_digest ~ '^[0-9a-f]{64}$'),
    projection_digest char(64) NOT NULL CHECK (projection_digest ~ '^[0-9a-f]{64}$'),
    receipt_json jsonb NOT NULL CHECK (jsonb_typeof(receipt_json) = 'object' AND octet_length(receipt_json::text) <= 33554432),
    received_at timestamptz NOT NULL,
    PRIMARY KEY (catalog_scope_id, producer_id, producer_version),
    UNIQUE (catalog_scope_id, producer_id, source_operation_id),
    UNIQUE (catalog_scope_id, producer_id, producer_version, receipt_id),
    FOREIGN KEY (catalog_scope_id, producer_id, producer_version) REFERENCES rbac3_catalog_manifest (catalog_scope_id, producer_id, producer_version),
    CHECK (source_version = manifest_digest)
);

ALTER TABLE rbac3_catalog_manifest ADD CONSTRAINT fk_catalog_ready_receipt FOREIGN KEY (catalog_scope_id, producer_id, producer_version, metadata_receipt_id) REFERENCES rbac3_catalog_source_receipt (catalog_scope_id, producer_id, producer_version, receipt_id);

CREATE TABLE rbac3_catalog_deployment_qualification (
    id bigint NOT NULL CHECK (id > 0),
    catalog_scope_id bigint NOT NULL CHECK (catalog_scope_id > 0),
    producer_id varchar(128) NOT NULL CHECK (producer_id ~ '^[A-Za-z0-9][A-Za-z0-9._:/-]*$'),
    producer_version bigint NOT NULL CHECK (producer_version > 0),
    artifact_digest char(64) NOT NULL CHECK (artifact_digest ~ '^[0-9a-f]{64}$'),
    manifest_digest char(64) NOT NULL CHECK (manifest_digest ~ '^[0-9a-f]{64}$'),
    policy_digest char(64) NOT NULL CHECK (policy_digest ~ '^[0-9a-f]{64}$'),
    pipeline_id varchar(256) NOT NULL,
    build_id varchar(256) NOT NULL,
    source_ref varchar(256) NOT NULL,
    commit varchar(64) NOT NULL CHECK (commit ~ '^([0-9a-f]{40}|[0-9a-f]{64})$'),
    deployment_id varchar(256) NOT NULL,
    readiness_digest char(64) NOT NULL CHECK (readiness_digest ~ '^[0-9a-f]{64}$'),
    trusted_issuer varchar(2048) NOT NULL,
    trusted_client_id varchar(200) NOT NULL,
    trusted_resource varchar(2048) NOT NULL,
    verified_at timestamptz NOT NULL,
    expires_at timestamptz NOT NULL,
    original_receipt_json jsonb NOT NULL CHECK (jsonb_typeof(original_receipt_json) = 'object' AND octet_length(original_receipt_json::text) <= 33554432),
    PRIMARY KEY (id),
    UNIQUE (catalog_scope_id, producer_id, id),
    UNIQUE (catalog_scope_id, producer_id, producer_version, id),
    FOREIGN KEY (catalog_scope_id, producer_id, producer_version) REFERENCES rbac3_catalog_manifest (catalog_scope_id, producer_id, producer_version),
    CHECK (expires_at > verified_at)
);

CREATE TABLE rbac3_catalog_activation (
    catalog_scope_id bigint NOT NULL CHECK (catalog_scope_id > 0),
    activation_version bigint NOT NULL CHECK (activation_version > 0),
    operation_id varchar(36) NOT NULL CHECK (operation_id ~ '^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$'),
    expected_active_revision bigint NOT NULL DEFAULT 0 CHECK (expected_active_revision >= 0),
    request_digest char(64) NOT NULL CHECK (request_digest ~ '^[0-9a-f]{64}$'),
    descriptor_json jsonb NOT NULL CHECK (jsonb_typeof(descriptor_json) = 'object' AND octet_length(descriptor_json::text) <= 33554432),
    descriptor_digest char(64) NOT NULL CHECK (descriptor_digest ~ '^[0-9a-f]{64}$'),
    producer_count integer NOT NULL CHECK (producer_count BETWEEN 1 AND 256),
    policy_version bigint NOT NULL DEFAULT 0 CHECK (policy_version >= 0),
    created_at timestamptz NOT NULL,
    created_by varchar(128) NOT NULL,
    PRIMARY KEY (catalog_scope_id, activation_version),
    UNIQUE (catalog_scope_id, operation_id),
    FOREIGN KEY (catalog_scope_id) REFERENCES rbac3_catalog_scope (id),
    CHECK (activation_version = expected_active_revision + 1)
);

CREATE TABLE rbac3_catalog_activation_producer (
    catalog_scope_id bigint NOT NULL CHECK (catalog_scope_id > 0),
    activation_version bigint NOT NULL CHECK (activation_version > 0),
    producer_id varchar(128) NOT NULL CHECK (producer_id ~ '^[A-Za-z0-9][A-Za-z0-9._:/-]*$'),
    producer_version bigint NOT NULL CHECK (producer_version > 0),
    manifest_digest char(64) NOT NULL CHECK (manifest_digest ~ '^[0-9a-f]{64}$'),
    policy_digest char(64) NOT NULL CHECK (policy_digest ~ '^[0-9a-f]{64}$'),
    metadata_digest char(64) NOT NULL CHECK (metadata_digest ~ '^[0-9a-f]{64}$'),
    source_version char(64) NOT NULL CHECK (source_version ~ '^[0-9a-f]{64}$'),
    qualification_id bigint NOT NULL CHECK (qualification_id > 0),
    PRIMARY KEY (catalog_scope_id, activation_version, producer_id),
    FOREIGN KEY (catalog_scope_id, activation_version) REFERENCES rbac3_catalog_activation (catalog_scope_id, activation_version),
    FOREIGN KEY (catalog_scope_id, producer_id, producer_version) REFERENCES rbac3_catalog_manifest (catalog_scope_id, producer_id, producer_version),
    FOREIGN KEY (catalog_scope_id, producer_id, producer_version, qualification_id) REFERENCES rbac3_catalog_deployment_qualification (catalog_scope_id, producer_id, producer_version, id),
    CHECK (source_version = manifest_digest)
);

CREATE TABLE rbac3_catalog_active_pointer (
    catalog_scope_id bigint NOT NULL CHECK (catalog_scope_id > 0),
    activation_version bigint CHECK (activation_version > 0),
    revision bigint NOT NULL DEFAULT 0 CHECK (revision >= 0),
    policy_version bigint NOT NULL DEFAULT 0 CHECK (policy_version >= 0),
    version bigint NOT NULL DEFAULT 0 CHECK (version >= 0),
    updated_at timestamptz NOT NULL,
    updated_by varchar(128) NOT NULL,
    PRIMARY KEY (catalog_scope_id),
    FOREIGN KEY (catalog_scope_id) REFERENCES rbac3_catalog_scope (id),
    FOREIGN KEY (catalog_scope_id, activation_version) REFERENCES rbac3_catalog_activation (catalog_scope_id, activation_version),
    CHECK ((activation_version IS NULL AND revision = 0) OR (activation_version IS NOT NULL AND revision = activation_version))
);

CREATE TABLE rbac3_catalog_role_binding (
    catalog_scope_id bigint NOT NULL CHECK (catalog_scope_id > 0),
    role_id bigint NOT NULL CHECK (role_id > 0),
    tenant_id bigint NOT NULL CHECK (tenant_id > 0),
    application_id bigint NOT NULL CHECK (application_id > 0),
    permission_version bigint NOT NULL DEFAULT 0 CHECK (permission_version >= 0),
    enabled boolean NOT NULL DEFAULT true,
    version bigint NOT NULL DEFAULT 0 CHECK (version >= 0),
    created_at timestamptz NOT NULL,
    created_by varchar(128) NOT NULL,
    updated_at timestamptz NOT NULL,
    updated_by varchar(128) NOT NULL,
    PRIMARY KEY (catalog_scope_id, role_id),
    FOREIGN KEY (catalog_scope_id, tenant_id, application_id) REFERENCES rbac3_catalog_scope (id, tenant_id, application_id),
    FOREIGN KEY (tenant_id, application_id, role_id) REFERENCES rbac3_role (tenant_id, application_id, id)
);

CREATE TABLE rbac3_catalog_role_permission (
    catalog_scope_id bigint NOT NULL CHECK (catalog_scope_id > 0),
    role_id bigint NOT NULL CHECK (role_id > 0),
    permission_id bigint NOT NULL CHECK (permission_id > 0),
    status varchar(32) NOT NULL DEFAULT 'ACTIVE' CHECK (status IN ('ACTIVE','DISABLED')),
    valid_from timestamptz NOT NULL,
    valid_to timestamptz,
    version bigint NOT NULL DEFAULT 0 CHECK (version >= 0),
    created_at timestamptz NOT NULL,
    created_by varchar(128) NOT NULL,
    updated_at timestamptz NOT NULL,
    updated_by varchar(128) NOT NULL,
    PRIMARY KEY (catalog_scope_id, role_id, permission_id),
    FOREIGN KEY (catalog_scope_id, role_id) REFERENCES rbac3_catalog_role_binding (catalog_scope_id, role_id),
    FOREIGN KEY (catalog_scope_id, permission_id) REFERENCES rbac3_catalog_permission (catalog_scope_id, id),
    CHECK (valid_to IS NULL OR valid_to > valid_from)
);

CREATE INDEX ix_catalog_role_permission_lookup ON rbac3_catalog_role_permission (catalog_scope_id, permission_id, status);

CREATE TABLE rbac3_catalog_effective_snapshot (
    id bigint NOT NULL CHECK (id > 0),
    catalog_scope_id bigint NOT NULL CHECK (catalog_scope_id > 0),
    tenant_id bigint NOT NULL CHECK (tenant_id > 0),
    user_id bigint NOT NULL CHECK (user_id > 0),
    issuer varchar(2048) NOT NULL,
    subject varchar(256) NOT NULL,
    auth_version bigint NOT NULL DEFAULT 0 CHECK (auth_version >= 0),
    tenant_policy_version bigint NOT NULL DEFAULT 0 CHECK (tenant_policy_version >= 0),
    catalog_version bigint NOT NULL CHECK (catalog_version > 0),
    role_context_digest char(64) NOT NULL CHECK (role_context_digest ~ '^[0-9a-f]{64}$'),
    snapshot_digest char(64) NOT NULL CHECK (snapshot_digest ~ '^[0-9a-f]{64}$'),
    snapshot_json jsonb NOT NULL CHECK (jsonb_typeof(snapshot_json) = 'object' AND octet_length(snapshot_json::text) <= 16777216),
    expires_at timestamptz NOT NULL,
    created_at timestamptz NOT NULL,
    PRIMARY KEY (id),
    UNIQUE (catalog_scope_id, user_id, id, auth_version, tenant_policy_version, catalog_version, role_context_digest),
    FOREIGN KEY (catalog_scope_id, tenant_id) REFERENCES rbac3_catalog_scope (id, tenant_id),
    FOREIGN KEY (tenant_id, user_id) REFERENCES rbac3_user (tenant_id, id),
    FOREIGN KEY (catalog_scope_id, catalog_version) REFERENCES rbac3_catalog_activation (catalog_scope_id, activation_version),
    CHECK (expires_at > created_at)
);

CREATE INDEX ix_catalog_snapshot_lookup ON rbac3_catalog_effective_snapshot
    (catalog_scope_id, user_id, auth_version, tenant_policy_version, catalog_version, role_context_digest, expires_at);

CREATE TABLE rbac3_catalog_snapshot_head (
    catalog_scope_id bigint NOT NULL CHECK (catalog_scope_id > 0),
    user_id bigint NOT NULL CHECK (user_id > 0),
    snapshot_id bigint NOT NULL CHECK (snapshot_id > 0),
    auth_version bigint NOT NULL DEFAULT 0 CHECK (auth_version >= 0),
    tenant_policy_version bigint NOT NULL DEFAULT 0 CHECK (tenant_policy_version >= 0),
    catalog_version bigint NOT NULL CHECK (catalog_version > 0),
    role_context_digest char(64) NOT NULL CHECK (role_context_digest ~ '^[0-9a-f]{64}$'),
    fence_version bigint NOT NULL DEFAULT 0 CHECK (fence_version >= 0),
    version bigint NOT NULL DEFAULT 0 CHECK (version >= 0),
    updated_at timestamptz NOT NULL,
    PRIMARY KEY (catalog_scope_id, user_id),
    FOREIGN KEY (catalog_scope_id, user_id, snapshot_id, auth_version, tenant_policy_version, catalog_version, role_context_digest) REFERENCES rbac3_catalog_effective_snapshot (catalog_scope_id, user_id, id, auth_version, tenant_policy_version, catalog_version, role_context_digest)
);

CREATE TABLE rbac3_catalog_rebuild_task (
    id bigint NOT NULL CHECK (id > 0),
    catalog_scope_id bigint NOT NULL CHECK (catalog_scope_id > 0),
    user_id bigint CHECK (user_id > 0),
    requested_auth_version bigint CHECK (requested_auth_version >= 0),
    requested_policy_version bigint NOT NULL DEFAULT 0 CHECK (requested_policy_version >= 0),
    requested_catalog_version bigint NOT NULL DEFAULT 0 CHECK (requested_catalog_version >= 0),
    command_id varchar(128) NOT NULL CHECK (command_id ~ '^[A-Za-z0-9][A-Za-z0-9._:/-]*$'),
    state varchar(32) NOT NULL DEFAULT 'PENDING' CHECK (state IN ('PENDING','RUNNING','SUCCEEDED','FAILED')),
    attempt integer NOT NULL DEFAULT 0 CHECK (attempt >= 0),
    next_attempt_at timestamptz NOT NULL,
    owner varchar(128),
    lease_token varchar(128),
    lease_generation bigint NOT NULL DEFAULT 0 CHECK (lease_generation >= 0),
    lease_until timestamptz,
    deadline timestamptz NOT NULL,
    failure_code varchar(128),
    version bigint NOT NULL DEFAULT 0 CHECK (version >= 0),
    created_at timestamptz NOT NULL,
    updated_at timestamptz NOT NULL,
    PRIMARY KEY (id),
    UNIQUE (catalog_scope_id, command_id),
    FOREIGN KEY (catalog_scope_id) REFERENCES rbac3_catalog_scope (id),
    FOREIGN KEY (user_id) REFERENCES rbac3_user (id),
    CHECK ((user_id IS NULL) = (requested_auth_version IS NULL)),
    CHECK ((state = 'RUNNING') = (owner IS NOT NULL AND lease_token IS NOT NULL AND lease_until IS NOT NULL)),
    CHECK (state = 'RUNNING' OR (owner IS NULL AND lease_token IS NULL AND lease_until IS NULL)),
    CHECK (lease_until IS NULL OR lease_until <= deadline),
    CHECK (deadline > created_at),
    CHECK ((state = 'FAILED') = (failure_code IS NOT NULL))
);

CREATE INDEX ix_catalog_rebuild_due ON rbac3_catalog_rebuild_task (next_attempt_at, id) WHERE state = 'PENDING';

CREATE INDEX ix_catalog_rebuild_lease ON rbac3_catalog_rebuild_task (lease_until, id) WHERE state = 'RUNNING';

CREATE TABLE rbac3_catalog_runtime_projection (
    projection_kind varchar(32) NOT NULL CHECK (projection_kind IN ('USER','TENANT','CHECKPOINT','GATEWAY')),
    projection_key varchar(256) NOT NULL,
    tenant_id bigint NOT NULL CHECK (tenant_id > 0),
    auth_version bigint NOT NULL DEFAULT 0 CHECK (auth_version >= 0),
    policy_version bigint NOT NULL DEFAULT 0 CHECK (policy_version >= 0),
    payload_json jsonb NOT NULL CHECK (jsonb_typeof(payload_json) = 'object' AND octet_length(payload_json::text) <= 16777216),
    checksum char(64) NOT NULL CHECK (checksum ~ '^[0-9a-f]{64}$'),
    ready boolean NOT NULL DEFAULT false,
    updated_at timestamptz NOT NULL,
    PRIMARY KEY (projection_kind, projection_key),
    FOREIGN KEY (tenant_id) REFERENCES rbac3_tenant_authorization_state (tenant_id),
    CHECK (length(projection_key)>0)
);

ALTER TABLE rbac3_data_rule ADD COLUMN catalog_scope_id bigint NOT NULL;
ALTER TABLE rbac3_data_rule DROP CONSTRAINT fk_rbac3_data_rule_permission_global;
ALTER TABLE rbac3_data_rule ADD CONSTRAINT fk_data_rule_catalog_permission
    FOREIGN KEY (catalog_scope_id, permission_id) REFERENCES rbac3_catalog_permission (catalog_scope_id, id);
ALTER TABLE rbac3_data_rule ADD CONSTRAINT fk_data_rule_catalog_role
    FOREIGN KEY (catalog_scope_id, role_id) REFERENCES rbac3_catalog_role_binding (catalog_scope_id, role_id);
ALTER TABLE rbac3_data_rule ADD CONSTRAINT fk_data_rule_catalog_scope
    FOREIGN KEY (catalog_scope_id, tenant_id, application_id) REFERENCES rbac3_catalog_scope (id, tenant_id, application_id);
CREATE INDEX ix_data_rule_catalog ON rbac3_data_rule (catalog_scope_id, role_id, permission_id, status);

-- Immutable historical facts cannot be rewritten by retry or governance commands.
CREATE FUNCTION rbac3_catalog_reject_mutation() RETURNS trigger LANGUAGE plpgsql AS $body$
BEGIN
    RAISE EXCEPTION 'RBAC_CATALOG_IMMUTABLE_FACT' USING ERRCODE = '55000';
END;
$body$;

-- TG_ARGV lists the only mutable columns; all identities and creation facts stay fixed.
CREATE FUNCTION rbac3_catalog_version_guard() RETURNS trigger LANGUAGE plpgsql AS $body$
BEGIN
    IF TG_OP = 'DELETE' THEN
        RAISE EXCEPTION 'RBAC_CATALOG_DELETE_FORBIDDEN' USING ERRCODE = '55000';
    END IF;
    IF (to_jsonb(NEW) - TG_ARGV) IS DISTINCT FROM (to_jsonb(OLD) - TG_ARGV)
        OR NEW.version <> OLD.version + 1 THEN
        RAISE EXCEPTION 'RBAC_CATALOG_IDENTITY_OR_VERSION_CONFLICT' USING ERRCODE = '55000';
    END IF;
    RETURN NEW;
END;
$body$;

CREATE FUNCTION rbac3_catalog_scope_identity_guard() RETURNS trigger LANGUAGE plpgsql AS $body$
BEGIN
    IF NOT EXISTS (SELECT 1 FROM rbac3_application a WHERE a.id = NEW.application_id
        AND a.application_code = NEW.application_code AND a.ddc_business_id = NEW.ddc_business_id
        AND a.ddc_application_id = NEW.ddc_application_id) THEN
        RAISE EXCEPTION 'RBAC_CATALOG_APPLICATION_IDENTITY_MISMATCH' USING ERRCODE = '23514';
    END IF;
    RETURN NEW;
END;
$body$;
CREATE TRIGGER tr_catalog_scope_identity BEFORE INSERT ON rbac3_catalog_scope
    FOR EACH ROW EXECUTE FUNCTION rbac3_catalog_scope_identity_guard();

CREATE FUNCTION rbac3_catalog_revision_guard() RETURNS trigger LANGUAGE plpgsql AS $body$
BEGIN
    IF NEW.current_revision < OLD.current_revision OR NEW.current_revision > OLD.current_revision + 1 THEN
        RAISE EXCEPTION 'RBAC_CATALOG_PRODUCER_REVISION_CONFLICT' USING ERRCODE = '23514';
    END IF;
    RETURN NEW;
END;
$body$;
CREATE TRIGGER tr_catalog_producer_revision BEFORE UPDATE ON rbac3_catalog_producer
    FOR EACH ROW EXECUTE FUNCTION rbac3_catalog_revision_guard();

CREATE FUNCTION rbac3_catalog_retirement_guard() RETURNS trigger LANGUAGE plpgsql AS $body$
BEGIN
    IF OLD.governance_state = 'RETIRED' AND NEW.governance_state <> 'RETIRED' THEN
        RAISE EXCEPTION 'RBAC_CATALOG_RETIRED_IDENTITY_CANNOT_BE_REUSED' USING ERRCODE = '23514';
    END IF;
    RETURN NEW;
END;
$body$;
CREATE TRIGGER tr_catalog_resource_retirement BEFORE UPDATE ON rbac3_catalog_resource
    FOR EACH ROW EXECUTE FUNCTION rbac3_catalog_retirement_guard();
CREATE TRIGGER tr_catalog_permission_retirement BEFORE UPDATE ON rbac3_catalog_permission
    FOR EACH ROW EXECUTE FUNCTION rbac3_catalog_retirement_guard();

CREATE FUNCTION rbac3_catalog_definition_guard() RETURNS trigger LANGUAGE plpgsql AS $body$
BEGIN
    IF NOT EXISTS (SELECT 1 FROM rbac3_catalog_manifest m WHERE m.catalog_scope_id = NEW.catalog_scope_id
        AND m.producer_id = NEW.producer_id AND m.producer_version = NEW.producer_version AND m.state = 'REGISTERED') THEN
        RAISE EXCEPTION 'RBAC_CATALOG_DEFINITION_ALREADY_SEALED' USING ERRCODE = '23514';
    END IF;
    IF TG_TABLE_NAME = 'rbac3_catalog_resource_version' THEN
        IF NOT EXISTS (SELECT 1 FROM rbac3_catalog_resource r WHERE r.catalog_scope_id = NEW.catalog_scope_id
            AND r.id = NEW.resource_id AND r.registration_key = NEW.registration_key
            AND r.resource_type = NEW.resource_type AND r.owner_producer_id = NEW.producer_id)
            OR (NEW.definition_json->>'key') IS DISTINCT FROM NEW.registration_key
            OR (NEW.definition_json->>'type') IS DISTINCT FROM NEW.resource_type
            OR (NEW.definition_json->>'access') IS DISTINCT FROM NEW.classification
            OR (NEW.definition_json->>'lifecycle') IS DISTINCT FROM NEW.definition_lifecycle
            OR (NEW.definition_json->'target') IS DISTINCT FROM NEW.target_json
            OR (NEW.definition_json->'i18n') IS DISTINCT FROM NEW.i18n_json
            OR NOT EXISTS (SELECT 1 FROM rbac3_catalog_manifest m,
                LATERAL jsonb_array_elements(m.canonical_manifest->'resources') d
                WHERE m.catalog_scope_id = NEW.catalog_scope_id AND m.producer_id = NEW.producer_id
                  AND m.producer_version = NEW.producer_version AND d = NEW.definition_json) THEN
            RAISE EXCEPTION 'RBAC_CATALOG_RESOURCE_DEFINITION_MISMATCH' USING ERRCODE = '23514';
        END IF;
    ELSE
        IF NOT EXISTS (SELECT 1 FROM rbac3_catalog_permission p WHERE p.catalog_scope_id = NEW.catalog_scope_id
            AND p.id = NEW.permission_id AND p.permission_code = NEW.permission_code
            AND p.owner_producer_id = NEW.producer_id AND p.meaning = NEW.definition_json->>'meaning')
            OR (NEW.definition_json->>'code') IS DISTINCT FROM NEW.permission_code
            OR (NEW.definition_json->>'lifecycle') IS DISTINCT FROM NEW.lifecycle
            OR (NEW.definition_json->'i18n') IS DISTINCT FROM NEW.i18n_json
            OR NOT EXISTS (SELECT 1 FROM rbac3_catalog_manifest m,
                LATERAL jsonb_array_elements(m.canonical_manifest->'permissionDefinitions') d
                WHERE m.catalog_scope_id = NEW.catalog_scope_id AND m.producer_id = NEW.producer_id
                  AND m.producer_version = NEW.producer_version AND d = NEW.definition_json) THEN
            RAISE EXCEPTION 'RBAC_CATALOG_PERMISSION_DEFINITION_MISMATCH' USING ERRCODE = '23514';
        END IF;
    END IF;
    RETURN NEW;
END;
$body$;
CREATE TRIGGER tr_catalog_resource_definition BEFORE INSERT ON rbac3_catalog_resource_version
    FOR EACH ROW EXECUTE FUNCTION rbac3_catalog_definition_guard();
CREATE TRIGGER tr_catalog_permission_definition BEFORE INSERT ON rbac3_catalog_permission_version
    FOR EACH ROW EXECUTE FUNCTION rbac3_catalog_definition_guard();

CREATE FUNCTION rbac3_catalog_requirement_guard() RETURNS trigger LANGUAGE plpgsql AS $body$
BEGIN
    IF NOT EXISTS (SELECT 1 FROM rbac3_catalog_manifest m WHERE m.catalog_scope_id = NEW.catalog_scope_id
        AND m.producer_id = NEW.producer_id AND m.producer_version = NEW.producer_version AND m.state = 'REGISTERED') THEN
        RAISE EXCEPTION 'RBAC_CATALOG_DEFINITION_ALREADY_SEALED' USING ERRCODE = '23514';
    END IF;
    IF NEW.permission_id IS NOT NULL AND NOT EXISTS (SELECT 1 FROM rbac3_catalog_permission p
        WHERE p.catalog_scope_id = NEW.catalog_scope_id AND p.id = NEW.permission_id
          AND p.permission_code = NEW.permission_code) THEN
        RAISE EXCEPTION 'RBAC_CATALOG_PERMISSION_REFERENCE_MISMATCH' USING ERRCODE = '23514';
    END IF;
    IF EXISTS (SELECT 1 FROM rbac3_catalog_resource_requirement r
        WHERE r.catalog_scope_id = NEW.catalog_scope_id AND r.producer_id = NEW.producer_id
          AND r.producer_version = NEW.producer_version AND r.resource_id = NEW.resource_id
          AND r.operation = NEW.operation AND r.group_index = NEW.group_index AND r.group_mode <> NEW.group_mode) THEN
        RAISE EXCEPTION 'RBAC_CATALOG_REQUIREMENT_GROUP_MISMATCH' USING ERRCODE = '23514';
    END IF;
    RETURN NEW;
END;
$body$;
CREATE TRIGGER tr_catalog_requirement_guard BEFORE INSERT ON rbac3_catalog_resource_requirement
    FOR EACH ROW EXECUTE FUNCTION rbac3_catalog_requirement_guard();

CREATE FUNCTION rbac3_catalog_receipt_guard() RETURNS trigger LANGUAGE plpgsql AS $body$
BEGIN
    IF NOT EXISTS (SELECT 1 FROM rbac3_catalog_manifest m JOIN rbac3_catalog_scope s ON s.id = m.catalog_scope_id
        WHERE m.catalog_scope_id = NEW.catalog_scope_id AND m.producer_id = NEW.producer_id
        AND m.producer_version = NEW.producer_version AND m.source_operation_id = NEW.source_operation_id
        AND m.manifest_digest = NEW.manifest_digest AND m.policy_digest = NEW.policy_digest AND m.metadata_digest = NEW.metadata_digest
        AND NEW.receipt_json->>'receiptId' = NEW.receipt_id
        AND NEW.receipt_json->>'operationId' = NEW.source_operation_id
        AND NEW.receipt_json->>'producerId' = NEW.producer_id
        AND NEW.receipt_json->>'producerVersion' = NEW.producer_version::text
        AND NEW.receipt_json->>'sourceVersion' = NEW.source_version
        AND NEW.receipt_json->>'projectionDigest' = NEW.projection_digest
        AND NEW.receipt_json->'digests'->>'manifestDigest' = NEW.manifest_digest
        AND NEW.receipt_json->'digests'->>'policyDigest' = NEW.policy_digest
        AND NEW.receipt_json->'digests'->>'metadataDigest' = NEW.metadata_digest
        AND NEW.receipt_json->>'resourceCount' = m.resource_count::text
        AND NEW.receipt_json->>'permissionCount' = m.permission_count::text
        AND NEW.receipt_json->>'messageCount' = m.message_count::text
        AND NEW.receipt_json->'scope' = jsonb_build_object('catalogScopeId',s.id::text,'tenantId',s.tenant_id::text,
            'businessCode',s.business_code,'applicationCode',s.application_code,'namespaceCode',s.namespace_code,'environment',s.environment)) THEN
        RAISE EXCEPTION 'RBAC_CATALOG_SOURCE_RECEIPT_MISMATCH' USING ERRCODE = '23514';
    END IF;
    RETURN NEW;
END;
$body$;
CREATE TRIGGER tr_catalog_receipt_guard BEFORE INSERT ON rbac3_catalog_source_receipt
    FOR EACH ROW EXECUTE FUNCTION rbac3_catalog_receipt_guard();

CREATE FUNCTION rbac3_catalog_manifest_state_guard() RETURNS trigger LANGUAGE plpgsql AS $body$
BEGIN
    IF NEW.state = 'METADATA_PENDING' AND (
        NEW.resource_count <> (SELECT count(*) FROM rbac3_catalog_resource_version v WHERE v.catalog_scope_id = NEW.catalog_scope_id
            AND v.producer_id = NEW.producer_id AND v.producer_version = NEW.producer_version)
        OR NEW.permission_count <> (SELECT count(*) FROM rbac3_catalog_permission_version v WHERE v.catalog_scope_id = NEW.catalog_scope_id
            AND v.producer_id = NEW.producer_id AND v.producer_version = NEW.producer_version)
        OR jsonb_array_length(NEW.canonical_manifest->'resources') IS DISTINCT FROM NEW.resource_count
        OR jsonb_array_length(NEW.canonical_manifest->'permissionDefinitions') IS DISTINCT FROM NEW.permission_count
        OR jsonb_array_length(NEW.canonical_manifest->'messages') IS DISTINCT FROM NEW.message_count
        OR NEW.canonical_manifest->'producer'->>'snapshotMode' IS DISTINCT FROM 'FULL') THEN
        RAISE EXCEPTION 'RBAC_CATALOG_MANIFEST_INCOMPLETE' USING ERRCODE = '23514';
    END IF;
    IF OLD.state = 'READY' OR (OLD.state <> NEW.state AND NOT (
        (OLD.state = 'REGISTERED' AND NEW.state IN ('METADATA_PENDING','FAILED')) OR
        (OLD.state = 'METADATA_PENDING' AND NEW.state IN ('READY','FAILED')) OR
        (OLD.state = 'FAILED' AND NEW.state = 'METADATA_PENDING'))) THEN
        RAISE EXCEPTION 'RBAC_CATALOG_MANIFEST_STATE_CONFLICT' USING ERRCODE = '23514';
    END IF;
    RETURN NEW;
END;
$body$;
CREATE TRIGGER tr_catalog_manifest_state BEFORE UPDATE ON rbac3_catalog_manifest
    FOR EACH ROW EXECUTE FUNCTION rbac3_catalog_manifest_state_guard();

CREATE FUNCTION rbac3_catalog_qualification_guard() RETURNS trigger LANGUAGE plpgsql AS $body$
BEGIN
    IF NOT EXISTS (SELECT 1 FROM rbac3_catalog_manifest m WHERE m.catalog_scope_id = NEW.catalog_scope_id
        AND m.producer_id = NEW.producer_id AND m.producer_version = NEW.producer_version
        AND m.manifest_digest = NEW.manifest_digest AND m.policy_digest = NEW.policy_digest
        AND m.commit = NEW.commit AND m.build_id = NEW.build_id) THEN
        RAISE EXCEPTION 'RBAC_CATALOG_QUALIFICATION_MANIFEST_MISMATCH' USING ERRCODE = '23514';
    END IF;
    RETURN NEW;
END;
$body$;
CREATE TRIGGER tr_catalog_qualification_guard BEFORE INSERT ON rbac3_catalog_deployment_qualification
    FOR EACH ROW EXECUTE FUNCTION rbac3_catalog_qualification_guard();

CREATE FUNCTION rbac3_catalog_activation_member_guard() RETURNS trigger LANGUAGE plpgsql AS $body$
BEGIN
    IF NOT EXISTS (SELECT 1 FROM rbac3_catalog_manifest m
        JOIN rbac3_catalog_deployment_qualification q ON q.catalog_scope_id = m.catalog_scope_id
          AND q.producer_id = m.producer_id AND q.producer_version = m.producer_version AND q.id = NEW.qualification_id
        JOIN rbac3_catalog_activation a ON a.catalog_scope_id = m.catalog_scope_id AND a.activation_version = NEW.activation_version
        WHERE m.catalog_scope_id = NEW.catalog_scope_id AND m.producer_id = NEW.producer_id
          AND m.producer_version = NEW.producer_version AND m.state = 'READY'
          AND m.manifest_digest = NEW.manifest_digest AND m.policy_digest = NEW.policy_digest
          AND m.metadata_digest = NEW.metadata_digest AND q.verified_at <= a.created_at AND q.expires_at > a.created_at) THEN
        RAISE EXCEPTION 'RBAC_CATALOG_ACTIVATION_MEMBER_NOT_READY' USING ERRCODE = '23514';
    END IF;
    RETURN NEW;
END;
$body$;
CREATE TRIGGER tr_catalog_activation_member BEFORE INSERT ON rbac3_catalog_activation_producer
    FOR EACH ROW EXECUTE FUNCTION rbac3_catalog_activation_member_guard();

CREATE FUNCTION rbac3_catalog_activation_complete_guard() RETURNS trigger LANGUAGE plpgsql AS $body$
DECLARE
    member_count integer;
BEGIN
    SELECT count(*) INTO member_count FROM rbac3_catalog_activation_producer p
        WHERE p.catalog_scope_id = NEW.catalog_scope_id AND p.activation_version = NEW.activation_version;
    IF NOT EXISTS (SELECT 1 FROM rbac3_catalog_scope s WHERE s.id = NEW.catalog_scope_id
        AND NEW.descriptor_json->'scope' = jsonb_build_object('catalogScopeId',s.id::text,'tenantId',s.tenant_id::text,
            'businessCode',s.business_code,'applicationCode',s.application_code,'namespaceCode',s.namespace_code,'environment',s.environment)) THEN
        RAISE EXCEPTION 'RBAC_CATALOG_DESCRIPTOR_SCOPE_MISMATCH' USING ERRCODE = '23514';
    END IF;
    IF member_count <> NEW.producer_count OR jsonb_typeof(NEW.descriptor_json->'producers') IS DISTINCT FROM 'array'
        OR jsonb_array_length(NEW.descriptor_json->'producers') <> member_count
        OR NEW.descriptor_json->>'activationVersion' IS DISTINCT FROM NEW.activation_version::text
        OR NEW.descriptor_json->>'policyVersion' IS DISTINCT FROM NEW.policy_version::text
        OR NEW.descriptor_json->>'operationId' IS DISTINCT FROM NEW.operation_id
        OR NEW.descriptor_json->'scope'->>'catalogScopeId' IS DISTINCT FROM NEW.catalog_scope_id::text THEN
        RAISE EXCEPTION 'RBAC_CATALOG_ACTIVATION_INCOMPLETE' USING ERRCODE = '23514';
    END IF;
    IF EXISTS (SELECT 1 FROM rbac3_catalog_activation_producer p
        JOIN rbac3_catalog_deployment_qualification q ON q.id = p.qualification_id
        WHERE p.catalog_scope_id = NEW.catalog_scope_id AND p.activation_version = NEW.activation_version
          AND NOT EXISTS (SELECT 1 FROM jsonb_array_elements(NEW.descriptor_json->'producers') j
            WHERE j->>'producerId' = p.producer_id AND j->>'producerVersion' = p.producer_version::text
              AND j->>'sourceVersion' = p.source_version AND j->>'qualificationId' = p.qualification_id::text
              AND j->>'artifactDigest' = q.artifact_digest AND j->'digests'->>'manifestDigest' = p.manifest_digest
              AND j->'digests'->>'policyDigest' = p.policy_digest AND j->'digests'->>'metadataDigest' = p.metadata_digest)) THEN
        RAISE EXCEPTION 'RBAC_CATALOG_DESCRIPTOR_MEMBER_MISMATCH' USING ERRCODE = '23514';
    END IF;
    RETURN NEW;
END;
$body$;
CREATE CONSTRAINT TRIGGER tr_catalog_activation_complete AFTER INSERT ON rbac3_catalog_activation
    DEFERRABLE INITIALLY DEFERRED FOR EACH ROW EXECUTE FUNCTION rbac3_catalog_activation_complete_guard();

CREATE FUNCTION rbac3_catalog_pointer_guard() RETURNS trigger LANGUAGE plpgsql AS $body$
BEGIN
    IF TG_OP = 'INSERT' THEN
        IF NEW.revision <> 0 OR NEW.activation_version IS NOT NULL OR NEW.version <> 0 THEN
            RAISE EXCEPTION 'RBAC_CATALOG_POINTER_MUST_START_EMPTY' USING ERRCODE = '23514';
        END IF;
    ELSE
        IF NEW.revision <> OLD.revision + 1 OR NEW.policy_version <= OLD.policy_version
            OR NOT EXISTS (SELECT 1 FROM rbac3_catalog_activation a WHERE a.catalog_scope_id = NEW.catalog_scope_id
                AND a.activation_version = NEW.activation_version AND a.expected_active_revision = OLD.revision
                AND a.policy_version = NEW.policy_version) THEN
            RAISE EXCEPTION 'RBAC_CATALOG_ACTIVE_POINTER_CONFLICT' USING ERRCODE = '23514';
        END IF;
    END IF;
    RETURN NEW;
END;
$body$;
CREATE TRIGGER tr_catalog_pointer_guard BEFORE INSERT OR UPDATE ON rbac3_catalog_active_pointer
    FOR EACH ROW EXECUTE FUNCTION rbac3_catalog_pointer_guard();

CREATE FUNCTION rbac3_catalog_rebuild_subject_guard() RETURNS trigger LANGUAGE plpgsql AS $body$
BEGIN
    IF NEW.user_id IS NOT NULL AND NOT EXISTS (SELECT 1 FROM rbac3_user u JOIN rbac3_catalog_scope s
        ON s.tenant_id = u.tenant_id WHERE u.id = NEW.user_id AND s.id = NEW.catalog_scope_id) THEN
        RAISE EXCEPTION 'RBAC_CATALOG_REBUILD_SUBJECT_SCOPE_MISMATCH' USING ERRCODE = '23514';
    END IF;
    RETURN NEW;
END;
$body$;
CREATE TRIGGER tr_catalog_rebuild_subject BEFORE INSERT ON rbac3_catalog_rebuild_task
    FOR EACH ROW EXECUTE FUNCTION rbac3_catalog_rebuild_subject_guard();

CREATE TRIGGER tr_catalog_resource_version_immutable BEFORE UPDATE OR DELETE ON rbac3_catalog_resource_version
    FOR EACH ROW EXECUTE FUNCTION rbac3_catalog_reject_mutation();

CREATE TRIGGER tr_catalog_resource_requirement_immutable BEFORE UPDATE OR DELETE ON rbac3_catalog_resource_requirement
    FOR EACH ROW EXECUTE FUNCTION rbac3_catalog_reject_mutation();

CREATE TRIGGER tr_catalog_permission_version_immutable BEFORE UPDATE OR DELETE ON rbac3_catalog_permission_version
    FOR EACH ROW EXECUTE FUNCTION rbac3_catalog_reject_mutation();

CREATE TRIGGER tr_catalog_registration_plan_immutable BEFORE UPDATE OR DELETE ON rbac3_catalog_registration_plan
    FOR EACH ROW EXECUTE FUNCTION rbac3_catalog_reject_mutation();

CREATE TRIGGER tr_catalog_registration_operation_immutable BEFORE UPDATE OR DELETE ON rbac3_catalog_registration_operation
    FOR EACH ROW EXECUTE FUNCTION rbac3_catalog_reject_mutation();

CREATE TRIGGER tr_catalog_source_receipt_immutable BEFORE UPDATE OR DELETE ON rbac3_catalog_source_receipt
    FOR EACH ROW EXECUTE FUNCTION rbac3_catalog_reject_mutation();

CREATE TRIGGER tr_catalog_deployment_qualification_immutable BEFORE UPDATE OR DELETE ON rbac3_catalog_deployment_qualification
    FOR EACH ROW EXECUTE FUNCTION rbac3_catalog_reject_mutation();

CREATE TRIGGER tr_catalog_activation_immutable BEFORE UPDATE OR DELETE ON rbac3_catalog_activation
    FOR EACH ROW EXECUTE FUNCTION rbac3_catalog_reject_mutation();

CREATE TRIGGER tr_catalog_activation_producer_immutable BEFORE UPDATE OR DELETE ON rbac3_catalog_activation_producer
    FOR EACH ROW EXECUTE FUNCTION rbac3_catalog_reject_mutation();

CREATE TRIGGER tr_catalog_effective_snapshot_immutable BEFORE UPDATE OR DELETE ON rbac3_catalog_effective_snapshot
    FOR EACH ROW EXECUTE FUNCTION rbac3_catalog_reject_mutation();

CREATE TRIGGER tr_catalog_scope_version BEFORE UPDATE OR DELETE ON rbac3_catalog_scope
    FOR EACH ROW EXECUTE FUNCTION rbac3_catalog_version_guard('status', 'version', 'updated_at', 'updated_by');

CREATE TRIGGER tr_catalog_producer_version BEFORE UPDATE OR DELETE ON rbac3_catalog_producer
    FOR EACH ROW EXECUTE FUNCTION rbac3_catalog_version_guard('owned_key_prefixes', 'owned_permission_prefixes', 'owned_message_prefixes', 'expected_modules', 'current_revision', 'enabled', 'version', 'updated_at', 'updated_by');

CREATE TRIGGER tr_catalog_service_grant_version BEFORE UPDATE OR DELETE ON rbac3_catalog_service_grant
    FOR EACH ROW EXECUTE FUNCTION rbac3_catalog_version_guard('capabilities', 'allowed_source_refs', 'allow_permission_expansion', 'enabled', 'version', 'updated_at', 'updated_by');

CREATE TRIGGER tr_catalog_resource_version BEFORE UPDATE OR DELETE ON rbac3_catalog_resource
    FOR EACH ROW EXECUTE FUNCTION rbac3_catalog_version_guard('owner_producer_id', 'governance_state', 'version', 'updated_at', 'updated_by');

CREATE TRIGGER tr_catalog_permission_version BEFORE UPDATE OR DELETE ON rbac3_catalog_permission
    FOR EACH ROW EXECUTE FUNCTION rbac3_catalog_version_guard('owner_producer_id', 'governance_state', 'version', 'updated_at', 'updated_by');

CREATE TRIGGER tr_catalog_manifest_version BEFORE UPDATE OR DELETE ON rbac3_catalog_manifest
    FOR EACH ROW EXECUTE FUNCTION rbac3_catalog_version_guard('state', 'metadata_receipt_id', 'failure_code', 'version', 'updated_at');

CREATE TRIGGER tr_catalog_message_owner_version BEFORE UPDATE OR DELETE ON rbac3_catalog_message_owner
    FOR EACH ROW EXECUTE FUNCTION rbac3_catalog_version_guard('owner_producer_id', 'lifecycle', 'version', 'updated_at', 'updated_by');

CREATE TRIGGER tr_catalog_active_pointer_version BEFORE UPDATE OR DELETE ON rbac3_catalog_active_pointer
    FOR EACH ROW EXECUTE FUNCTION rbac3_catalog_version_guard('activation_version', 'revision', 'policy_version', 'version', 'updated_at', 'updated_by');

CREATE TRIGGER tr_catalog_role_binding_version BEFORE UPDATE OR DELETE ON rbac3_catalog_role_binding
    FOR EACH ROW EXECUTE FUNCTION rbac3_catalog_version_guard('permission_version', 'enabled', 'version', 'updated_at', 'updated_by');

CREATE TRIGGER tr_catalog_role_permission_version BEFORE UPDATE OR DELETE ON rbac3_catalog_role_permission
    FOR EACH ROW EXECUTE FUNCTION rbac3_catalog_version_guard('status', 'valid_from', 'valid_to', 'version', 'updated_at', 'updated_by');

CREATE TRIGGER tr_catalog_snapshot_head_version BEFORE UPDATE OR DELETE ON rbac3_catalog_snapshot_head
    FOR EACH ROW EXECUTE FUNCTION rbac3_catalog_version_guard('snapshot_id', 'auth_version', 'tenant_policy_version', 'catalog_version', 'role_context_digest', 'fence_version', 'version', 'updated_at');

CREATE TRIGGER tr_catalog_rebuild_task_version BEFORE UPDATE OR DELETE ON rbac3_catalog_rebuild_task
    FOR EACH ROW EXECUTE FUNCTION rbac3_catalog_version_guard('state', 'attempt', 'next_attempt_at', 'owner', 'lease_token', 'lease_generation', 'lease_until', 'failure_code', 'version', 'updated_at');
