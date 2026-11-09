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

    def test_role_is_rls_scoped_and_cannot_delete(self):
        if not self.test_role:
            self.skipTest("DORKER_TEST_POSTGRES_ROLE is not configured")
        conn = self.repository._connect()
        try:
            with conn.cursor() as cursor:
                cursor.execute(
                    "SELECT current_user, "
                    "has_table_privilege(current_user, 'remote_audit.events', 'SELECT'), "
                    "has_table_privilege(current_user, 'remote_audit.events', 'INSERT'), "
                    "has_table_privilege(current_user, 'remote_audit.events', 'DELETE'), "
                    "has_table_privilege(current_user, 'remote_audit.heads', 'UPDATE')"
                )
                role, can_select, can_insert, can_delete, can_update_head = cursor.fetchone()
                self.assertEqual(role, "remote_audit_app")
                self.assertTrue(can_select)
                self.assertTrue(can_insert)
                self.assertFalse(can_delete)
                self.assertTrue(can_update_head)
                cursor.execute(
                    "SELECT bool_and(c.relrowsecurity) FROM pg_class c "
                    "JOIN pg_namespace n ON n.oid = c.relnamespace "
                    "WHERE n.nspname = 'remote_audit' AND c.relkind = 'r'"
                )
                self.assertTrue(cursor.fetchone()[0])
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


if __name__ == "__main__":
    unittest.main()
