"""Read-only smoke test for the deployed Supabase remote-audit login role."""
from __future__ import annotations

import os
import sys
from pathlib import Path

import psycopg

# Running a script sets sys.path[0] to scripts/, not the agent-lab package root.
AGENT_LAB_ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(AGENT_LAB_ROOT))

from dorker_agent.postgres_audit_repository import PostgresAuditRepository


def main() -> int:
    dsn = os.environ.get("SUPABASE_AUDIT_DSN", "").strip()
    if not dsn:
        print("SUPABASE_AUDIT_DSN is required", file=sys.stderr)
        return 2

    # Direct-login identity and least-privilege checks. No writes are performed.
    with psycopg.connect(dsn, connect_timeout=2, application_name="dorker-audit-smoke") as conn:
        with conn.cursor() as cur:
            cur.execute(
                """
                SELECT current_user, session_user,
                       r.rolcanlogin, r.rolsuper, r.rolcreatedb,
                       r.rolcreaterole, r.rolreplication, r.rolbypassrls,
                       r.rolinherit,
                       pg_has_role(current_user, 'remote_audit_app', 'USAGE'),
                       has_schema_privilege(current_user, 'remote_audit', 'USAGE'),
                       has_schema_privilege(current_user, 'remote_audit', 'CREATE'),
                       has_table_privilege(current_user, 'remote_audit.events', 'SELECT'),
                       has_table_privilege(current_user, 'remote_audit.events', 'INSERT'),
                       has_table_privilege(current_user, 'remote_audit.events', 'UPDATE'),
                       has_table_privilege(current_user, 'remote_audit.events', 'DELETE'),
                       has_table_privilege(current_user, 'remote_audit.events', 'TRUNCATE'),
                       has_table_privilege(current_user, 'remote_audit.heads', 'UPDATE'),
                       row_security_active('remote_audit.events'::regclass),
                       row_security_active('remote_audit.heads'::regclass),
                       (SELECT count(*) FROM pg_auth_members m
                         JOIN pg_roles member_role ON member_role.oid = m.member
                         WHERE member_role.rolname = current_user)
                FROM pg_roles r
                WHERE r.rolname = current_user
                """
            )
            row = cur.fetchone()
            if row is None:
                raise RuntimeError("connected role was not found in pg_roles")

            (
                current_user, session_user, can_login, superuser, createdb,
                createrole, replication, bypassrls, inherit, app_role,
                schema_usage, schema_create, events_select, events_insert,
                events_update, events_delete, events_truncate, heads_update,
                events_rls, heads_rls, membership_count,
            ) = row

            checks = {
                "current_user": current_user == "remote_audit_login",
                "session_user": session_user == "remote_audit_login",
                "LOGIN": can_login,
                "INHERIT": inherit,
                "NOSUPERUSER": not superuser,
                "NOCREATEDB": not createdb,
                "NOCREATEROLE": not createrole,
                "NOREPLICATION": not replication,
                "NOBYPASSRLS": not bypassrls,
                "remote_audit_app membership": app_role,
                "exactly one role membership": membership_count == 1,
                "schema USAGE": schema_usage,
                "no schema CREATE": not schema_create,
                "events SELECT": events_select,
                "events INSERT": events_insert,
                "events UPDATE denied": not events_update,
                "events DELETE denied": not events_delete,
                "events TRUNCATE denied": not events_truncate,
                "heads UPDATE": heads_update,
                "RLS active on events": events_rls,
                "RLS active on heads": heads_rls,
            }
            failed = [name for name, passed in checks.items() if not passed]
            for name, passed in checks.items():
                print(f"{'PASS' if passed else 'FAIL'} {name}")
            if failed:
                raise RuntimeError("least-privilege checks failed: " + ", ".join(failed))

            cur.execute("SET statement_timeout = '3s'; SET lock_timeout = '1s'")
            cur.execute("SELECT pg_database_size(current_database())")
            database_bytes = cur.fetchone()[0]
            database_write_ceiling = 450_000_000
            database_budget_ok = database_bytes < database_write_ceiling
            print(
                f"{'PASS' if database_budget_ok else 'FAIL'} database size budget "
                f"({database_bytes} bytes; ceiling {database_write_ceiling})"
            )
            if not database_budget_ok:
                raise RuntimeError("database size reached the 90% Free-plan operating ceiling")

    # Exercise the production adapter's read/verification path using the same
    # direct-login DSN. Repository 0 is a read-only empty-chain probe.
    repository = PostgresAuditRepository.from_dsn(dsn)
    if not repository.verify(0):
        raise RuntimeError("adapter verify(0) did not validate the empty chain")
    print("PASS adapter verify(0)")
    print("Supabase audit direct-login smoke test passed; no rows were written.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
