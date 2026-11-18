# GitHub Local AI Workbench

A GitHub Actions-native, CPU-only local-model reviewer. It uses an ephemeral GitHub-hosted
Ubuntu runner and a versioned Ollama container; no external AI API key is required.

## Agent Lab integration

The Workbench uses the provider-agnostic `dorker_agent.Agent` and its
`ChatModel` port for each review chunk. `workbench/ollama_chat_model.py` is the
Ollama adapter: it translates the Agent Lab system/user message contract into
`/api/generate` requests and preserves Ollama completion metadata for the
existing truncation and token-budget checks. The adapter is request-scoped; do
not share one instance across concurrent requests.

The workflow adds the sibling `agent-lab` package to `PYTHONPATH` for both
unit tests and inference. When running the Workbench locally, use:

```bash
PYTHONPATH=../agent-lab python -m unittest -v
PYTHONPATH=../agent-lab python local_ai.py
```

This is a single-turn Agent integration. It does not add autonomous planning,
tool execution, multi-step memory, or a general-purpose context manager.

## Current scope

- Manual run (workflow_dispatch) with an optional review prompt.
- Pull-request review (pull_request) with read-only repository permissions.
- Reusable workflow (workflow_call) so another repository can call this workflow.
- Qwen 2.5 1.5B through Ollama, downloaded at run time and executed locally on CPU.
- Bounded Git diff context, common-secret redaction, timeout, output-contract validation,
  Ollama completion/token-usage checks, and a Markdown artifact.
- The model output is advisory. It cannot write files, create commits, approve PRs, merge,
  deploy, or access repository secrets.

## Run manually

Open **Actions → Local AI Workbench → Run workflow**. Optionally provide a prompt.
Download the local-ai-review artifact after the job completes.

## Reuse from another repository

Use the same full 40-character commit SHA in both the reusable workflow reference and
implementation_ref. This prevents the workflow definition and the Python implementation from
silently drifting onto different revisions.

```yaml
name: Local AI Review
on:
  pull_request:
    types: [opened, synchronize, reopened]
permissions:
  contents: read
jobs:
  review:
    uses: loxchi-s/dorker-skills/.github/workflows/local-ai-workbench.yml@FULL_40_CHARACTER_SHA
    with:
      implementation_ref: FULL_40_CHARACTER_SHA
      prompt: "Review Modularity, Boundaries, Coupling, Cohesion, and Testability; report actionable findings with exact changed-file evidence."
```

Replace FULL_40_CHARACTER_SHA with the same immutable commit SHA in both locations.
The called workflow validates the input format and verifies that the fetched implementation
commit exactly matches implementation_ref before running tests or inference. The external
implementation is fetched without credentials.

The reusable workflow checks out the caller repository for Git diff collection. In-repository
runs use the checked-out Workbench files so that the branch's changes can be tested and reviewed.

The caller must allow reusable workflows from loxchi-s/dorker-skills under its Actions
settings. For private repositories, confirm GitHub's reusable-workflow access policy.

## Resource profile

- Runner: GitHub-hosted ubuntu-latest; actual CPU/RAM allocation depends on GitHub plan.
- Ollama container: capped at 2 CPU cores, 4 GiB RAM, and 256 processes.
- Model: qwen2.5:1.5b; model weights are downloaded on each fresh runner unless a cache is
  added later. No GPU is requested.
- Job timeout: 70 minutes; model review is split into diff chunks capped at 6,000 UTF-8
  bytes per chunk and 300,000 UTF-8 bytes total. A single changed file can span multiple chunks;
  at most 64 changed files and 64 review chunks are processed. The review inference phase
  has a 60-minute total budget and each model request has a maximum 120-second timeout.
  The workflow step fails after writing and uploading the report whenever the aggregate verdict
  is INCOMPLETE; artifact upload and container cleanup still run.
  Each request uses an 8,192-token context window and reserves up to 1,536 output tokens.
  The input ceiling is 90% of the configured context window, further reduced when necessary
  to preserve the output reserve. A conservative UTF-8 byte upper-bound estimator plus a
  128-token framing reserve rejects oversized requests before inference; this is not an exact
  model tokenizer. Actual `prompt_eval_count` and `done_reason` are checked after inference.
  Any truncated, skipped, timed-out, oversized, output-limited, or invalid chunk forces the
  aggregate report verdict to INCOMPLETE.
- Reports include Ollama's `prompt_eval_count`, `eval_count`, and `done_reason`. The report is
  marked `INCOMPLETE` when completion metadata is missing, generation stops with
  `done_reason=length`, the prompt plus output budget reaches the context limit, or the model
  response fails the evidence-based review contract. This is a post-inference safety check; it
  does not prove that no prompt truncation occurred.
- Parallelism: one model job per workflow run. Repository-level concurrency cancels superseded
  runs for the same ref.

## Execution contract

- **Execution model:** one GitHub Actions job owns one review run. The Workbench process is a
  bounded, synchronous coordinator that collects the caller diff, splits oversized file diffs
  into UTF-8-safe segments, invokes local Ollama requests sequentially per segment, validates
  each response, and writes one aggregate Markdown report.
- **Concurrency and identity:** GitHub Actions concurrency is keyed by repository and ref, with
  superseded runs cancelled. The durable execution identity is the GitHub run ID and attempt;
  the report records workflow commit and PR head commit separately. Each run uploads a
  run-specific artifact.
- **State ownership:** no mutable shared application state, database, or external queue is used.
  Intermediate state lives only in process memory and the ephemeral runner's temporary directory.
  GitHub Actions owns run status; the uploaded artifact is the retained review output.
- **Failure semantics:** unit-test failure stops inference. A per-file model timeout, malformed
  response, output-limit stop, context truncation, omitted file, or invalid finding contract
  marks the aggregate verdict INCOMPLETE. A failed chunk does not erase validated findings from
  other chunks. There are no automatic inference retries; rerun the workflow explicitly.
- **Durability and cleanup:** reports are uploaded with a run-specific name and seven-day
  retention. The Ollama container is removed in an always-run cleanup step. Runner-local state
  is otherwise disposable; no result is written back to the caller repository.
- **Resource bounds:** at most 64 changed files, 64 review chunks, 6,000 UTF-8 bytes per chunk, 300,000 bytes total,
  60 minutes of inference time, and 120 seconds per model request. The GitHub job timeout is
  70 minutes. Exceeding a review bound is reported as incomplete, not silently treated as a
  complete review. The workflow check fails closed on an INCOMPLETE verdict after preserving
  the report artifact and cleaning up the model container.

## Security boundaries

- contents:read; checkout does not persist credentials.
- No repository secrets are passed to the model process or Ollama container.
- In-repository pull-request runs execute the Workbench Python code and unit tests from the
  pull-request revision. This is untrusted code execution on an ephemeral GitHub-hosted runner;
  it is not a sandbox or a trusted-code verification boundary. The job has read-only repository
  permissions and receives no repository secrets. Do not add secrets or write permissions to
  this job, and do not use self-hosted runners for untrusted pull requests.
- External reusable callers execute the Workbench implementation from the exact commit SHA
  supplied through implementation_ref; callers must use the same SHA in the reusable workflow
  reference and the input. Their repository checkout is used as Git data for diff collection.
- Common credential patterns and PEM private-key blocks are redacted before inference. This
  is best-effort redaction, not a guarantee; never commit secrets to a repository.
- The model container has bounded CPU, memory and process count. It requires network access
  to download the container image and model weights. The workflow runner itself also requires
  network access.
- The workflow pins the Ollama 0.6.8 `linux/amd64` image manifest by digest:
  `sha256:6697852aa235e8fb4e1e77cfab9bbf70d51d3760cb0d266e9fb43cf2b8e44f66`.
  This prevents the image reference from silently changing when a tag is updated. The digest
  is architecture-specific; verify and update it deliberately when changing the runner platform
  or Ollama version. Source: https://hub.docker.com/layers/ollama/ollama/0.6.8/images/sha256-6697852aa235e8fb4e1e77cfab9bbf70d51d3760cb0d266e9fb43cf2b8e44f66?tab=layers
- Reports are written to the runner's temporary directory, never to a pre-existing file in the
  caller checkout. Missing reports are ignored on upload.
- No automatic retries for inference; rerun the failed workflow manually.

## Status

- Implemented in this branch: workflow, bounded local inference client, report artifact,
  reusable workflow contract, and unit tests.
- Agent Lab CI passed on commit 2c3d5b97: 248 tests passed, 5 skipped, and 5 Docker
  integration tests passed.
- The previous Local AI Workbench run was superseded because the 46-file, approximately
  263 KB PR diff exceeded the former 16-file/24-chunk/96 KB review bounds. It is not counted
  as a complete review.
- Expanded review bounds are implemented: 64 files, 64 chunks, 300 KB total diff context,
  and a 60-minute inference budget. The workflow timeout is 70 minutes. A fresh full-coverage
  GitHub Actions run is still required; no Local AI PASS is claimed yet.
- CodeRabbit manual review was requested with @coderabbitai review; no review findings have
  been returned yet.
- Not yet validated: external reusable-workflow invocation from the football repository,
  cold model download time, and model quality. Model findings remain advisory and low-confidence.
- Not a coding agent: it reviews diffs but does not edit source code or open pull requests.
