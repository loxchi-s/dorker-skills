from __future__ import annotations

import hashlib
import os
import unittest
from concurrent.futures import ThreadPoolExecutor

from dorker_agent.artifacts import VerifiedGitHubActor
from dorker_agent.postgres_audit_repository import PostgresAuditRepository
from dorker_agent.remote_audit_service import AuditServiceError

_DSN = os.environ.get("DORKER_TEST_POSTGRES_DSN")


@unittest.skipUnless(_DSN, "DORKER_TEST_POSTGRES_DSN is not configured")
class PostgresAuditRepositoryIntegrationTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        try:
            import psycopg  # noqa: F401
        except ImportError as exc:
            raise unittest.SkipTest("psycopg is not installed") from exc
        cls.test_role = os.environ.get("DORKER_TEST_POSTGRES_ROLE")
        role = cls.test_role
        if role:
            if not role.replace("_", "").isalnum():
                raise ValueError("invalid test database role")
            import psycopg
            from psycopg.rows import dict_row
            cls.repository = PostgresAuditRepository(
                lambda: psycopg.connect(
                    _DSN, row_factory=dict_row, connect_timeout=5,
                    application_name="dorker-remote-audit-test",
                    options=f"-c role={role}",
                )
            )
        else:
            cls.repository = PostgresAuditRepository.from_dsn(_DSN)
        cls.repository_id = int.from_bytes(os.urandom(8), "big") % (2**63 - 1) + 1
        cls.actor = VerifiedGitHubActor(910001, "postgres-adapter-test")

    def append_plan(self, key: str, token: str):
        return self.repository.append(
            repository_id=self.repository_id,
            idempotency_key=key,
            request_hash=hashlib.sha256(key.encode()).hexdigest(),
            event_type="gc_plan_created",
            actor=self.actor,
            details={"plan": {"fixture": key}},
            approval_token=token,
        )

    def test_role_membership_inherits_least_privilege_and_rls(self):
        if not self.test_role:
            self.skipTest("DORKER_TEST_POSTGRES_ROLE is not configured")
        conn = self.repository._connect()
        try:
            with conn.cursor() as cursor:
                cursor.execute(
                    "SELECT current_user, "
                    "pg_has_role(current_user, 'remote_audit_app', 'MEMBER') AS is_member, "
                    "has_table_privilege(current_user, 'remote_audit.events', 'SELECT') AS can_select, "
                    "has_table_privilege(current_user, 'remote_audit.events', 'INSERT') AS can_insert, "
                    "has_table_privilege(current_user, 'remote_audit.events', 'DELETE') AS can_delete, "
                    "has_table_privilege(current_user, 'remote_audit.heads', 'UPDATE') AS can_update_head, "
                    "(SELECT NOT rolinherit FROM pg_roles WHERE rolname = 'remote_audit_app') AS app_noinherit"
                )
                privileges = cursor.fetchone()
                self.assertEqual(privileges["current_user"], "remote_audit_login")
                self.assertTrue(privileges["is_member"])
                self.assertTrue(privileges["can_select"])
                self.assertTrue(privileges["can_insert"])
                self.assertFalse(privileges["can_delete"])
                self.assertTrue(privileges["can_update_head"])
                self.assertTrue(privileges["app_noinherit"])
                cursor.execute(
                    "SELECT bool_and(c.relrowsecurity) AS all_rls_enabled FROM pg_class c "
                    "JOIN pg_namespace n ON n.oid = c.relnamespace "
                    "WHERE n.nspname = 'remote_audit' AND c.relkind = 'r'"
                )
                self.assertTrue(cursor.fetchone()["all_rls_enabled"])
        finally:
            conn.rollback()
            conn.close()

    def test_idempotency_integrity_and_cross_connection_reads(self):
        token = hashlib.sha256(b"one-plan").hexdigest()
        first, replayed = self.append_plan("one-key", token)
        self.assertFalse(replayed)
        replay, was_replayed = self.append_plan("one-key", token)
        self.assertTrue(was_replayed)
        self.assertEqual(first, replay)
        self.assertEqual(self.repository.lookup(self.repository_id, "one-key"), first)
        self.assertEqual(self.repository.list_events(self.repository_id, 0, 10), [first])
        self.assertTrue(self.repository.verify(self.repository_id))

        with self.assertRaises(AuditServiceError) as conflict:
            self.repository.append(
                repository_id=self.repository_id,
                idempotency_key="one-key",
                request_hash=hashlib.sha256(b"different-request").hexdigest(),
                event_type="gc_plan_created",
                actor=self.actor,
                details={"plan": {"fixture": "different"}},
                approval_token=hashlib.sha256(b"different-plan").hexdigest(),
            )
        self.assertEqual(conflict.exception.code, "idempotency_conflict")

    def test_concurrent_first_appends_are_serialized(self):
        repository_id = self.repository_id + 1

        def write(index: int):
            key = f"parallel-{index}"
            token = hashlib.sha256(key.encode()).hexdigest()
            return self.repository.append(
                repository_id=repository_id,
                idempotency_key=key,
                request_hash=hashlib.sha256((key + "-request").encode()).hexdigest(),
                event_type="gc_plan_created",
                actor=self.actor,
                details={"plan": {"index": index}},
                approval_token=token,
            )

        with ThreadPoolExecutor(max_workers=8) as pool:
            results = list(pool.map(write, range(8)))
        self.assertTrue(all(not replayed for _, replayed in results))
        events = self.repository.list_events(repository_id, 0, 20)
        self.assertEqual([event["sequence"] for event in events], list(range(1, 9)))
        self.assertTrue(self.repository.verify(repository_id))

    def test_failed_late_write_rolls_back_event_and_head(self):
        admin_dsn = os.environ.get("DORKER_TEST_POSTGRES_ADMIN_DSN")
        if not admin_dsn:
            self.skipTest("DORKER_TEST_POSTGRES_ADMIN_DSN is not configured")

        import psycopg

        repository_id = self.repository_id + 2
        admin = psycopg.connect(admin_dsn)
        try:
            with admin.cursor() as cursor:
                cursor.execute("""
                    CREATE OR REPLACE FUNCTION remote_audit.test_reject_plan_insert()
                    RETURNS trigger LANGUAGE plpgsql AS $function$
                    BEGIN
                        RAISE EXCEPTION 'forced rollback integration test'
                            USING ERRCODE = 'P0001';
                    END;
                    $function$
                """)
                cursor.execute("""
                    CREATE TRIGGER test_reject_plan_insert
                    BEFORE INSERT ON remote_audit.plans
                    FOR EACH ROW EXECUTE FUNCTION remote_audit.test_reject_plan_insert()
                """)
            admin.commit()

            key = "rollback-late-write"
            with self.assertRaises(AuditServiceError) as failure:
                self.repository.append(
                    repository_id=repository_id,
                    idempotency_key=key,
                    request_hash=hashlib.sha256(key.encode()).hexdigest(),
                    event_type="gc_plan_created",
                    actor=self.actor,
                    details={"plan": {"fixture": key}},
                    approval_token=hashlib.sha256(key.encode()).hexdigest(),
                )
            self.assertEqual(failure.exception.code, "repository_unavailable")

            with admin.cursor() as cursor:
                cursor.execute(
                    "SELECT "
                    "(SELECT COUNT(*) FROM remote_audit.events WHERE repository_id = %s), "
                    "(SELECT COUNT(*) FROM remote_audit.heads WHERE repository_id = %s), "
                    "(SELECT COUNT(*) FROM remote_audit.plans WHERE repository_id = %s)",
                    (repository_id, repository_id, repository_id),
                )
                self.assertEqual(cursor.fetchone(), (0, 0, 0))
        finally:
            with admin.cursor() as cursor:
                cursor.execute(
                    "DROP TRIGGER IF EXISTS test_reject_plan_insert ON remote_audit.plans"
                )
                cursor.execute(
                    "DROP FUNCTION IF EXISTS remote_audit.test_reject_plan_insert()"
                )
            admin.commit()
            admin.close()


if __name__ == "__main__":
    unittest.main()
