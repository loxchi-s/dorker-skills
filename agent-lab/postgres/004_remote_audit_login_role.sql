-- Restricted direct-login role for the server-side PostgreSQL audit adapter.
-- No password is assigned here. Set its password through a secure Supabase
-- credential workflow before enabling any application connection.
BEGIN;

DO $create_login$
BEGIN
  IF NOT EXISTS (SELECT 1 FROM pg_roles WHERE rolname = 'remote_audit_login') THEN
    CREATE ROLE remote_audit_login
      LOGIN INHERIT
      NOSUPERUSER NOCREATEDB NOCREATEROLE NOREPLICATION NOBYPASSRLS;
  END IF;
END
$create_login$;

DO $login_guard$
DECLARE
  login_role record;
  login_oid oid;
  app_oid oid;
BEGIN
  SELECT oid, rolcanlogin, rolinherit, rolsuper, rolcreatedb,
         rolcreaterole, rolreplication, rolbypassrls
    INTO login_role
  FROM pg_roles
  WHERE rolname = 'remote_audit_login';
  login_oid := login_role.oid;

  IF NOT FOUND OR NOT login_role.rolcanlogin OR NOT login_role.rolinherit
     OR login_role.rolsuper OR login_role.rolcreatedb
     OR login_role.rolcreaterole OR login_role.rolreplication
     OR login_role.rolbypassrls THEN
    RAISE EXCEPTION 'remote_audit_login has unsafe role attributes';
  END IF;

  SELECT oid INTO app_oid FROM pg_roles WHERE rolname = 'remote_audit_app';
  IF app_oid IS NULL THEN
    RAISE EXCEPTION 'remote_audit_app does not exist';
  END IF;

  IF EXISTS (
    SELECT 1 FROM pg_auth_members
    WHERE member = login_oid AND roleid <> app_oid
  ) THEN
    RAISE EXCEPTION 'remote_audit_login has unexpected role memberships';
  END IF;

  IF EXISTS (
    SELECT 1 FROM pg_auth_members
    WHERE member = app_oid
  ) THEN
    RAISE EXCEPTION 'remote_audit_app must not inherit any parent roles';
  END IF;
END
$login_guard$;

DO $membership$
BEGIN
  IF NOT pg_has_role('remote_audit_login', 'remote_audit_app', 'MEMBER') THEN
    GRANT remote_audit_app TO remote_audit_login;
  END IF;
END
$membership$;

COMMENT ON ROLE remote_audit_login IS
  'Restricted LOGIN role for the server-side remote audit adapter; INHERITs only remote_audit_app; password must be provisioned out-of-band.';

COMMIT;
