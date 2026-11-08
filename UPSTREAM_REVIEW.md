# Upstream Skill Screening — Initial Review

Review date: 2026-11-08

This is a repository-level and selected-file screening, not a complete security audit. No upstream skill has been copied into the runtime registry or enabled.

## Decision summary

| Source | Pinned revision | Root license evidence | Decision |
|---|---|---|---|
| https://github.com/obra/superpowers | `22f0b463e7a5e579904dd6211a520321035526f7` | MIT, `LICENSE` | Select process skills for adaptation; do not import verbatim |
| https://github.com/trailofbits/skills | `e4dd0bb5b15535f7c5a0834187dffba6ac37e4ff` | CC BY-SA 4.0, `LICENSE` | Select security skills for a separate compliance-aware review |

## Superpowers — recommended candidates

Source revision: `22f0b463e7a5e579904dd6211a520321035526f7`

| Skill | Dorker use | Decision |
|---|---|---|
| `brainstorming` | Clarify requirements and compare designs before implementation | Adapt; preserve user's direct task instructions and avoid unnecessary questions |
| `writing-plans` | Produce bounded, file-specific implementation plans and test criteria | Adapt; require explicit approval before changes with external side effects |
| `test-driven-development` | Red/green/refactor workflow | Candidate; inspect full references and test commands before import |
| `systematic-debugging` | Evidence-led root-cause analysis | Candidate; inspect full references before import |
| `verification-before-completion` | Require fresh evidence before claiming tests or completion | Strong candidate; align with Dorker's status separation |

### Deferred from Superpowers

- `subagent-driven-development` and `dispatching-parallel-agents`: current Agent Lab has no subagent execution API or isolation contract.
- `using-git-worktrees`: assumes local Git and shell/worktree access; not suitable for the current GitHub-connector-only workflow without redesign.
- `executing-plans`: includes continuous execution and no check-in between tasks; Dorker must retain explicit approval for sensitive or external side effects.
- `using-superpowers`: contains mandatory skill-invocation instructions before every response/action. Do not import verbatim; its global control flow could override Dorker's own routing and policy.

MIT was confirmed in the repository root `LICENSE`. This does not replace checking any third-party assets or dependencies included with a selected skill.

## Trail of Bits — recommended candidates

Source revision: `e4dd0bb5b15535f7c5a0834187dffba6ac37e4ff`

| Skill | Dorker use | Decision |
|---|---|---|
| `agentic-actions-auditor` | Audit GitHub Actions that invoke coding agents; detect untrusted event input, prompt injection paths, unsafe permissions and sandbox bypasses | High priority; map unsupported tools to static GitHub-file inspection |
| `audit-context-building` | Build architecture/data-flow context before security review | High priority; adapt to available repository inspection tools |
| `code-improver` | Autonomous review/fix loop | Defer; expects Workflow/Task tools not present in current Agent Lab |

The repository root `LICENSE` states Creative Commons Attribution-ShareAlike 4.0 International (CC BY-SA 4.0). Any redistribution or adaptation must preserve required attribution and comply with ShareAlike terms. Confirm per-skill notices and third-party assets before copying.

## Import gates still required

1. Fetch the complete selected skill directory at the pinned commit, including references, scripts and assets.
2. Inspect all instructions for prompt injection, secret access, shell/network operations, destructive behavior and unsupported tool assumptions.
3. Record the exact source path, immutable commit, license/attribution, and SHA-256 of each imported file.
4. Adapt the skill to Dorker's capability policy and explicit approval model.
5. Add tests for parser compatibility, policy boundaries and expected workflow behavior.
6. Keep each candidate disabled until the review and tests are complete.

## Current status

- Repository metadata and root license files inspected for the two sources above.
- Selected Superpowers and Trail of Bits skill documents inspected.
- Candidate registry records pinned to immutable commit SHAs.
- No upstream content copied; no runtime permissions granted.
- File-level SHA-256 values not yet recorded because the files have not been imported.
- No CI run or execution test is claimed by this review.
