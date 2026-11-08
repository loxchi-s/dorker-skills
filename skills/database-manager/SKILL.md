---
name: database-manager
description: Designs and operates database schemas, migrations, queries and persistence workflows. Use when a task involves SQLite, PostgreSQL or Supabase data storage.
---
# Database Manager

## Workflow
1. Inspect schema, constraints, indexes, transaction boundaries and existing data.
2. Define ownership, consistency and durability requirements.
3. Make migrations reversible where practical and test against a disposable database.
4. Use parameterized queries and least-privilege roles.
5. Verify row counts, constraints and migration state after changes.

## Safety
Do not run destructive migrations, production writes or data exports without explicit approval. Never log credentials or sensitive rows.
