-- Dedicated non-login privilege role for the trusted server-side audit adapter.
-- Create a separate LOGIN role manually and grant it membership in this role.
-- This role intentionally has repository-wide access; it is not tenant isolation.

BEGIN;

DO $$
BEGIN
  IF NOT EXISTS (SELECT 1 FROM pg_roles WHERE rolname = 'remote_audit_app') THEN
    EXECUTE 'CREATE ROLE remote_audit_app NOLOGIN NOSUPERUSER NOCREATEDB NOCREATEROLE NOINHERIT NOBYPASSRLS';
  END IF;
END
$$;

ALTER ROLE remote_audit_app NOLOGIN NOSUPERUSER NOCREATEDB NOCREATEROLE NOINHERIT NOBYPASSRLS;

-- Fail closed if a pre-existing role has unsafe memberships or object ownership.
-- Do not silently mutate existing grants/ownership during a privilege migration.
DO $audit_guard$
DECLARE
  app_role_oid oid;
BEGIN
  SELECT oid INTO app_role_oid
  FROM pg_roles
  WHERE rolname = 'remote_audit_app';

  IF EXISTS (
    SELECT 1 FROM pg_auth_members
    WHERE member = app_role_oid
  ) THEN
    RAISE EXCEPTION
      'remote_audit_app must not be a member of any other role; audit memberships first';
  END IF;

  IF EXISTS (
    SELECT 1 FROM pg_namespace
    WHERE nspname = 'remote_audit'
      AND nspowner = app_role_oid
  ) OR EXISTS (
    SELECT 1 FROM pg_class
    WHERE relnamespace = 'remote_audit'::regnamespace
      AND relowner = app_role_oid
  ) OR EXISTS (
    SELECT 1 FROM pg_proc
    WHERE pronamespace = 'remote_audit'::regnamespace
      AND proowner = app_role_oid
  ) OR EXISTS (
    SELECT 1 FROM pg_type
    WHERE typnamespace = 'remote_audit'::regnamespace
      AND typowner = app_role_oid
  ) THEN
    RAISE EXCEPTION
      'remote_audit_app must not own the audit schema or its objects';
  END IF;

  IF EXISTS (
    SELECT 1
    FROM pg_policies p
    WHERE p.schemaname = 'remote_audit'
      AND NOT EXISTS (
        SELECT 1
        FROM (VALUES
          ('events'::name, 'remote_audit_app_events_select'::name, 'SELECT'::text, 'true'::text, NULL::text),
          ('events'::name, 'remote_audit_app_events_insert'::name, 'INSERT'::text, NULL::text, 'true'::text),
          ('heads'::name, 'remote_audit_app_heads_select'::name, 'SELECT'::text, 'true'::text, NULL::text),
          ('heads'::name, 'remote_audit_app_heads_insert'::name, 'INSERT'::text, NULL::text, 'true'::text),
          ('heads'::name, 'remote_audit_app_heads_update'::name, 'UPDATE'::text, 'true'::text, 'true'::text),
          ('plans'::name, 'remote_audit_app_plans_select'::name, 'SELECT'::text, 'true'::text, NULL::text),
          ('plans'::name, 'remote_audit_app_plans_insert'::name, 'INSERT'::text, NULL::text, 'true'::text),
          ('decisions'::name, 'remote_audit_app_decisions_select'::name, 'SELECT'::text, 'true'::text, NULL::text),
          ('decisions'::name, 'remote_audit_app_decisions_insert'::name, 'INSERT'::text, NULL::text, 'true'::text),
          ('consumed_evidence'::name, 'remote_audit_app_evidence_select'::name, 'SELECT'::text, 'true'::text, NULL::text),
          ('consumed_evidence'::name, 'remote_audit_app_evidence_insert'::name, 'INSERT'::text, NULL::text, 'true'::text)
        ) AS expected(tablename, policyname, cmd, qual, with_check)
        WHERE p.tablename = expected.tablename
          AND p.policyname = expected.policyname
          AND p.cmd = expected.cmd
          AND p.permissive = 'PERMISSIVE'
          AND p.roles = ARRAY['remote_audit_app']::name[]
          AND p.qual IS NOT DISTINCT FROM expected.qual
          AND p.with_check IS NOT DISTINCT FROM expected.with_check
      )
  ) OR (
    SELECT COUNT(*) FROM pg_policies WHERE schemaname = 'remote_audit'
  ) <> 11 THEN
    RAISE EXCEPTION
      'unexpected remote_audit RLS policy exists; review it before applying app-role policies';
  END IF;
END
$audit_guard$;
GRANT USAGE ON SCHEMA remote_audit TO remote_audit_app;

REVOKE ALL ON SCHEMA remote_audit FROM PUBLIC, anon, authenticated;
REVOKE ALL ON ALL TABLES IN SCHEMA remote_audit FROM PUBLIC, anon, authenticated;
REVOKE ALL ON ALL TABLES IN SCHEMA remote_audit FROM remote_audit_app;

GRANT SELECT, INSERT ON remote_audit.events TO remote_audit_app;
GRANT SELECT, INSERT, UPDATE ON remote_audit.heads TO remote_audit_app;
GRANT SELECT, INSERT ON remote_audit.plans TO remote_audit_app;
GRANT SELECT, INSERT ON remote_audit.decisions TO remote_audit_app;
GRANT SELECT, INSERT ON remote_audit.consumed_evidence TO remote_audit_app;

-- RLS must be enabled explicitly; policies alone do not enforce row security.
ALTER TABLE remote_audit.events ENABLE ROW LEVEL SECURITY;
ALTER TABLE remote_audit.heads ENABLE ROW LEVEL SECURITY;
ALTER TABLE remote_audit.plans ENABLE ROW LEVEL SECURITY;
ALTER TABLE remote_audit.decisions ENABLE ROW LEVEL SECURITY;
ALTER TABLE remote_audit.consumed_evidence ENABLE ROW LEVEL SECURITY;

DROP POLICY IF EXISTS remote_audit_app_events_select ON remote_audit.events;
CREATE POLICY remote_audit_app_events_select ON remote_audit.events
  FOR SELECT TO remote_audit_app USING (true);
DROP POLICY IF EXISTS remote_audit_app_events_insert ON remote_audit.events;
CREATE POLICY remote_audit_app_events_insert ON remote_audit.events
  FOR INSERT TO remote_audit_app WITH CHECK (true);

DROP POLICY IF EXISTS remote_audit_app_heads_select ON remote_audit.heads;
CREATE POLICY remote_audit_app_heads_select ON remote_audit.heads
  FOR SELECT TO remote_audit_app USING (true);
DROP POLICY IF EXISTS remote_audit_app_heads_insert ON remote_audit.heads;
CREATE POLICY remote_audit_app_heads_insert ON remote_audit.heads
  FOR INSERT TO remote_audit_app WITH CHECK (true);
DROP POLICY IF EXISTS remote_audit_app_heads_update ON remote_audit.heads;
CREATE POLICY remote_audit_app_heads_update ON remote_audit.heads
  FOR UPDATE TO remote_audit_app USING (true) WITH CHECK (true);

DROP POLICY IF EXISTS remote_audit_app_plans_select ON remote_audit.plans;
CREATE POLICY remote_audit_app_plans_select ON remote_audit.plans
  FOR SELECT TO remote_audit_app USING (true);
DROP POLICY IF EXISTS remote_audit_app_plans_insert ON remote_audit.plans;
CREATE POLICY remote_audit_app_plans_insert ON remote_audit.plans
  FOR INSERT TO remote_audit_app WITH CHECK (true);

DROP POLICY IF EXISTS remote_audit_app_decisions_select ON remote_audit.decisions;
CREATE POLICY remote_audit_app_decisions_select ON remote_audit.decisions
  FOR SELECT TO remote_audit_app USING (true);
DROP POLICY IF EXISTS remote_audit_app_decisions_insert ON remote_audit.decisions;
CREATE POLICY remote_audit_app_decisions_insert ON remote_audit.decisions
  FOR INSERT TO remote_audit_app WITH CHECK (true);

DROP POLICY IF EXISTS remote_audit_app_evidence_select ON remote_audit.consumed_evidence;
CREATE POLICY remote_audit_app_evidence_select ON remote_audit.consumed_evidence
  FOR SELECT TO remote_audit_app USING (true);
DROP POLICY IF EXISTS remote_audit_app_evidence_insert ON remote_audit.consumed_evidence;
CREATE POLICY remote_audit_app_evidence_insert ON remote_audit.consumed_evidence
  FOR INSERT TO remote_audit_app WITH CHECK (true);

COMMENT ON ROLE remote_audit_app IS
  'NOLOGIN least-privilege group role for the trusted remote audit adapter; repository-wide access, no tenant isolation.';

COMMIT;
