ALTER TABLE rbac3_authorization_mutation
    ADD COLUMN claim_owner varchar(36),
    ADD COLUMN claim_expires_at timestamp with time zone,
    ADD CONSTRAINT ck_authorization_mutation_claim
        CHECK ((claim_owner IS NULL) = (claim_expires_at IS NULL));

CREATE INDEX idx_authorization_mutation_claim
    ON rbac3_authorization_mutation (status, claim_expires_at, updated_at);
