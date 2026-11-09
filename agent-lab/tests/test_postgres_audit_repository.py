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
            details={"plan": {"approval_token": token, "fixture": key}},
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
                    "(SELECT rolcanlogin AND rolinherit AND NOT rolsuper AND NOT rolcreatedb "
                    "AND NOT rolcreaterole AND NOT rolreplication AND NOT rolbypassrls FROM pg_roles "
                    "WHERE rolname = current_user) AS login_role_restricted, "
                    "NOT EXISTS (SELECT 1 FROM pg_class c "
                    "JOIN pg_namespace n ON n.oid = c.relnamespace "
                    "JOIN pg_roles owner_role ON owner_role.oid = c.relowner "
                    "WHERE n.nspname = 'remote_audit' AND owner_role.rolname = current_user) "
                    "AS not_table_owner, "
                    "pg_has_role(current_user, 'remote_audit_app', 'MEMBER') AS is_member, "
                    "(SELECT COUNT(*) = 1 FROM pg_auth_members m "
                    "JOIN pg_roles granted_role ON granted_role.oid = m.roleid "
                    "JOIN pg_roles member_role ON member_role.oid = m.member "
                    "WHERE member_role.rolname = current_user "
                    "AND granted_role.rolname = 'remote_audit_app') AS only_expected_membership, "
                    "NOT EXISTS (SELECT 1 FROM pg_auth_members m "
                    "WHERE m.member = (SELECT oid FROM pg_roles WHERE rolname = 'remote_audit_app')) "
                    "AS app_role_has_no_parent_roles, "
                    "has_table_privilege(current_user, 'remote_audit.events', 'SELECT') AS can_select, "
                    "has_table_privilege(current_user, 'remote_audit.events', 'INSERT') AS can_insert, "
                    "has_table_privilege(current_user, 'remote_audit.events', 'UPDATE') AS can_update_events, "
                    "has_table_privilege(current_user, 'remote_audit.events', 'DELETE') AS can_delete, "
                    "has_table_privilege(current_user, 'remote_audit.events', 'TRUNCATE') AS can_truncate, "
                    "has_table_privilege(current_user, 'remote_audit.heads', 'UPDATE') AS can_update_head, "
                    "has_schema_privilege(current_user, 'remote_audit', 'CREATE') AS can_create_in_schema, "
                    "(SELECT NOT rolinherit AND NOT rolcanlogin AND NOT rolsuper "
                    "AND NOT rolcreatedb AND NOT rolcreaterole AND NOT rolreplication "
                    "AND NOT rolbypassrls FROM pg_roles "
                    "WHERE rolname = 'remote_audit_app') AS app_role_restricted, "
                    "NOT has_schema_privilege('anon', 'remote_audit', 'USAGE') AS anon_schema_denied, "
                    "NOT has_schema_privilege('authenticated', 'remote_audit', 'USAGE') AS authenticated_schema_denied, "
                    "NOT has_table_privilege('anon', 'remote_audit.events', 'SELECT') AS anon_select_denied, "
                    "NOT has_table_privilege('authenticated', 'remote_audit.events', 'SELECT') AS authenticated_select_denied"
                )
                privileges = cursor.fetchone()
                self.assertEqual(privileges["current_user"], "remote_audit_login")
                self.assertTrue(privileges["login_role_restricted"])
                self.assertTrue(privileges["not_table_owner"])
                self.assertTrue(privileges["is_member"])
                self.assertTrue(privileges["only_expected_membership"])
                self.assertTrue(privileges["app_role_has_no_parent_roles"])
                self.assertTrue(privileges["can_select"])
                self.assertTrue(privileges["can_insert"])
                self.assertFalse(privileges["can_update_events"])
                self.assertFalse(privileges["can_delete"])
                self.assertFalse(privileges["can_truncate"])
                self.assertTrue(privileges["can_update_head"])
                self.assertFalse(privileges["can_create_in_schema"])
                self.assertTrue(privileges["app_role_restricted"])
                self.assertTrue(privileges["anon_schema_denied"])
                self.assertTrue(privileges["authenticated_schema_denied"])
                self.assertTrue(privileges["anon_select_denied"])
                self.assertTrue(privileges["authenticated_select_denied"])
                cursor.execute(
                    "SELECT bool_and(c.relrowsecurity) AS all_rls_enabled, "
                    "bool_and(row_security_active(c.oid)) AS rls_active_for_login "
                    "FROM pg_class c JOIN pg_namespace n ON n.oid = c.relnamespace "
                    "WHERE n.nspname = 'remote_audit' AND c.relkind = 'r'"
                )
                rls = cursor.fetchone()
                self.assertTrue(rls["all_rls_enabled"])
                self.assertTrue(rls["rls_active_for_login"])
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

    def test_lost_commit_acknowledgement_replays_committed_event(self):
        import psycopg

        drop_acknowledgement = True

        class CommitAcknowledgementLoss:
            def __init__(self, connection):
                self._connection = connection

            def __getattr__(self, name):
                return getattr(self._connection, name)

            def commit(self):
                nonlocal drop_acknowledgement
                self._connection.commit()
                if drop_acknowledgement:
                    drop_acknowledgement = False
                    raise psycopg.OperationalError("simulated lost commit acknowledgement")

        def connect_with_one_lost_ack():
            return CommitAcknowledgementLoss(self.repository._connect())

        repository = PostgresAuditRepository(connect_with_one_lost_ack)
        repository_id = self.repository_id + 3
        key = "lost-commit-ack"
        request_hash = hashlib.sha256(key.encode()).hexdigest()
        token = hashlib.sha256((key + "-plan").encode()).hexdigest()
        kwargs = {
            "repository_id": repository_id,
            "idempotency_key": key,
            "request_hash": request_hash,
            "event_type": "gc_plan_created",
            "actor": self.actor,
            "details": {"plan": {"approval_token": token, "fixture": key}},
            "approval_token": token,
        }

        with self.assertRaises(AuditServiceError) as failure:
            repository.append(**kwargs)
        self.assertEqual(failure.exception.code, "repository_unavailable")
        self.assertTrue(failure.exception.retryable)

        event, replayed = repository.append(**kwargs)
        self.assertTrue(replayed)
        self.assertEqual(event["idempotency_key"], key)
        self.assertTrue(repository.verify(repository_id))
        self.assertEqual(repository.list_events(repository_id, 0, 10), [event])

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
                details={"plan": {"approval_token": token, "index": index}},
                approval_token=token,
            )

        with ThreadPoolExecutor(max_workers=8) as pool:
            results = list(pool.map(write, range(8)))
        self.assertTrue(all(not replayed for _, replayed in results))
        events = self.repository.list_events(repository_id, 0, 20)
        self.assertEqual([event["sequence"] for event in events], list(range(1, 9)))
        self.assertTrue(self.repository.verify(repository_id))

    def test_concurrent_same_idempotency_key_returns_one_committed_event(self):
        repository_id = self.repository_id + 4
        key = "parallel-same-key"
        token = hashlib.sha256((key + "-plan").encode()).hexdigest()
        request_hash = hashlib.sha256((key + "-request").encode()).hexdigest()

        def write(_index: int):
            return self.repository.append(
                repository_id=repository_id,
                idempotency_key=key,
                request_hash=request_hash,
                event_type="gc_plan_created",
                actor=self.actor,
                details={"plan": {"approval_token": token, "fixture": key}},
                approval_token=token,
            )

        with ThreadPoolExecutor(max_workers=8) as pool:
            results = list(pool.map(write, range(8)))

        events = [event for event, _ in results]
        replay_flags = [replayed for _, replayed in results]
        self.assertEqual(sum(not replayed for replayed in replay_flags), 1)
        self.assertEqual(sum(replayed for replayed in replay_flags), 7)
        self.assertTrue(all(event == events[0] for event in events))
        self.assertEqual(self.repository.list_events(repository_id, 0, 10), [events[0]])
        self.assertTrue(self.repository.verify(repository_id))

    def test_concurrent_idempotency_key_reuse_with_different_payload_conflicts(self):
        repository_id = self.repository_id + 5
        key = "parallel-conflicting-key"
        token = hashlib.sha256((key + "-plan").encode()).hexdigest()

        def write(index: int):
            try:
                return self.repository.append(
                    repository_id=repository_id,
                    idempotency_key=key,
                    request_hash=hashlib.sha256(f"{key}-{index}".encode()).hexdigest(),
                    event_type="gc_plan_created",
                    actor=self.actor,
                    details={"plan": {"approval_token": token, "variant": index}},
                    approval_token=token,
                )
            except AuditServiceError as exc:
                return exc

        with ThreadPoolExecutor(max_workers=8) as pool:
            results = list(pool.map(write, range(8)))

        committed = [item for item in results if isinstance(item, tuple)]
        conflicts = [item for item in results if isinstance(item, AuditServiceError)]
        self.assertEqual(len(committed), 1)
        self.assertEqual(len(conflicts), 7)
        self.assertTrue(all(item.code == "idempotency_conflict" for item in conflicts))
        self.assertEqual(len(self.repository.list_events(repository_id, 0, 10)), 1)
        self.assertTrue(self.repository.verify(repository_id))

    def test_hash_chain_detects_direct_payload_tampering(self):
        admin_dsn = os.environ.get("DORKER_TEST_POSTGRES_ADMIN_DSN")
        if not admin_dsn:
            self.skipTest("DORKER_TEST_POSTGRES_ADMIN_DSN is not configured")

        import psycopg

        repository_id = self.repository_id + 5
        key = "tamper-detection"
        token = hashlib.sha256((key + "-plan").encode()).hexdigest()
        event, replayed = self.repository.append(
            repository_id=repository_id,
            idempotency_key=key,
            request_hash=hashlib.sha256((key + "-request").encode()).hexdigest(),
            event_type="gc_plan_created",
            actor=self.actor,
            details={"plan": {"approval_token": token, "fixture": key}},
            approval_token=token,
        )
        self.assertFalse(replayed)

        with psycopg.connect(admin_dsn) as admin:
            with admin.cursor() as cursor:
                cursor.execute(
                    "UPDATE remote_audit.events "
                    "SET event_document = jsonb_set(event_document, "
                    "'{details,plan,fixture}', %s::jsonb) "
                    "WHERE repository_id = %s AND sequence = %s",
                    ('"tampered"', repository_id, event["sequence"]),
                )

        self.assertFalse(self.repository.verify(repository_id))
        with self.assertRaises(AuditServiceError) as failure:
            self.repository.lookup(repository_id, key)
        self.assertEqual(failure.exception.code, "integrity_violation")

    def test_hash_chain_verification_detects_plan_index_tampering(self):
        admin_dsn = os.environ.get("DORKER_TEST_POSTGRES_ADMIN_DSN")
        if not admin_dsn:
            self.skipTest("DORKER_TEST_POSTGRES_ADMIN_DSN is not configured")

        import psycopg

        repository_id = self.repository_id + 6
        key = "tampered-plan-index"
        token = hashlib.sha256((key + "-plan").encode()).hexdigest()
        event, replayed = self.repository.append(
            repository_id=repository_id,
            idempotency_key=key,
            request_hash=hashlib.sha256(key.encode()).hexdigest(),
            event_type="gc_plan_created",
            actor=self.actor,
            details={"plan": {"approval_token": token, "fixture": key}},
            approval_token=token,
        )
        self.assertFalse(replayed)

        with psycopg.connect(admin_dsn) as admin:
            with admin.cursor() as cursor:
                cursor.execute(
                    "UPDATE remote_audit.plans SET creator_actor_id = creator_actor_id + 1 "
                    "WHERE repository_id = %s AND plan_token = %s",
                    (repository_id, token),
                )
                # The index row is changed without touching the event hash.
                self.assertEqual(cursor.rowcount, 1)

        self.assertFalse(self.repository.verify(repository_id))
        with self.assertRaises(AuditServiceError) as failure:
            self.repository.lookup(repository_id, key)
        self.assertEqual(failure.exception.code, "integrity_violation")

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
            token = hashlib.sha256(key.encode()).hexdigest()
            with self.assertRaises(AuditServiceError) as failure:
                self.repository.append(
                    repository_id=repository_id,
                    idempotency_key=key,
                    request_hash=hashlib.sha256(key.encode()).hexdigest(),
                    event_type="gc_plan_created",
                    actor=self.actor,
                    details={"plan": {"approval_token": token, "fixture": key}},
                    approval_token=token,
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
