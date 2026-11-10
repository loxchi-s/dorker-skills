-- Cover the five foreign-key access paths reported by Supabase Performance Advisor.
-- These indexes are additive and safe for the currently empty audit tables.
BEGIN;
CREATE INDEX IF NOT EXISTS consumed_evidence_repository_event_idx
  ON remote_audit.consumed_evidence (repository_id, event_sequence);
CREATE INDEX IF NOT EXISTS consumed_evidence_repository_plan_idx
  ON remote_audit.consumed_evidence (repository_id, plan_token);
CREATE INDEX IF NOT EXISTS decisions_repository_event_idx
  ON remote_audit.decisions (repository_id, event_sequence);
CREATE INDEX IF NOT EXISTS heads_repository_sequence_idx
  ON remote_audit.heads (repository_id, sequence);
CREATE INDEX IF NOT EXISTS plans_repository_event_idx
  ON remote_audit.plans (repository_id, event_sequence);
COMMIT;
