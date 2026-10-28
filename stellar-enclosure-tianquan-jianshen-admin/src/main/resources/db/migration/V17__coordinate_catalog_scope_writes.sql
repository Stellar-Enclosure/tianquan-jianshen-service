CREATE FUNCTION rbac3_catalog_scope_write_fence() RETURNS trigger LANGUAGE plpgsql
    SET search_path FROM CURRENT AS $body$
DECLARE
    target_scope bigint;
BEGIN
    IF TG_OP = 'DELETE' THEN
        target_scope := OLD.catalog_scope_id;
    ELSE
        target_scope := NEW.catalog_scope_id;
    END IF;
    UPDATE rbac3_catalog_scope SET version = version + 1 WHERE id = target_scope;
    IF NOT FOUND THEN
        RAISE EXCEPTION 'RBAC_CATALOG_SCOPE_FENCE_MISSING' USING ERRCODE = '23503';
    END IF;
    IF TG_OP = 'DELETE' THEN
        RETURN OLD;
    END IF;
    RETURN NEW;
END;
$body$;

CREATE TRIGGER tr_catalog_active_pointer_scope_fence
    BEFORE INSERT OR UPDATE OR DELETE ON rbac3_catalog_active_pointer
    FOR EACH ROW EXECUTE FUNCTION rbac3_catalog_scope_write_fence();

CREATE TRIGGER tr_catalog_producer_scope_fence
    BEFORE INSERT OR UPDATE OR DELETE ON rbac3_catalog_producer
    FOR EACH ROW EXECUTE FUNCTION rbac3_catalog_scope_write_fence();

CREATE TRIGGER tr_catalog_service_grant_scope_fence
    BEFORE INSERT OR UPDATE OR DELETE ON rbac3_catalog_service_grant
    FOR EACH ROW EXECUTE FUNCTION rbac3_catalog_scope_write_fence();
