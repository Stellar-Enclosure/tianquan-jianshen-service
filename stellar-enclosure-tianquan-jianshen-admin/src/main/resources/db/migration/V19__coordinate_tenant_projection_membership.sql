CREATE FUNCTION rbac3_coordinate_projection_membership() RETURNS trigger
LANGUAGE plpgsql SET search_path FROM CURRENT AS $$
BEGIN
    IF TG_OP = 'UPDATE' AND OLD.tenant_id <> NEW.tenant_id THEN
        UPDATE rbac3_tenant_authorization_state SET version = version
         WHERE tenant_id = LEAST(OLD.tenant_id, NEW.tenant_id);
        UPDATE rbac3_tenant_authorization_state SET version = version
         WHERE tenant_id = GREATEST(OLD.tenant_id, NEW.tenant_id);
    ELSE
        UPDATE rbac3_tenant_authorization_state SET version = version
         WHERE tenant_id = CASE WHEN TG_OP = 'DELETE' THEN OLD.tenant_id ELSE NEW.tenant_id END;
    END IF;
    IF TG_OP = 'DELETE' THEN RETURN OLD; END IF;
    RETURN NEW;
END;
$$;

CREATE TRIGGER tr_rbac3_projection_membership
    BEFORE INSERT OR DELETE OR UPDATE OF tenant_id, id ON rbac3_user
    FOR EACH ROW EXECUTE FUNCTION rbac3_coordinate_projection_membership();
