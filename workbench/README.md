# GitHub Local AI Workbench

A GitHub Actions-native, CPU-only local-model reviewer. It uses an ephemeral GitHub-hosted
Ubuntu runner and a versioned Ollama container; no external AI API key is required.

## Current scope

- Manual run (`workflow_dispatch`) with an optional review prompt.
- Pull-request review (`pull_request`) with read-only repository permissions.
- Reusable workflow (`workflow_call`) so another repository can call this workflow.
- Qwen 2.5 1.5B through Ollama, downloaded at run time and executed locally on CPU.
- Bounded Git diff context, common-secret redaction, timeout, and a Markdown artifact.
- The model output is advisory. It cannot write files, create commits, approve PRs, merge,
  deploy, or access repository secrets.

## Run manually

Open **Actions → Local AI Workbench → Run workflow**. Optionally provide a prompt.
Download the `local-ai-review-<run_id>` artifact after the job completes.

## Reuse from another repository

Add a caller workflow in the target repository:

```yaml
name: Local AI Review
on:
  pull_request:
    types: [opened, synchronize, reopened]
permissions:
  contents: read
jobs:
  review:
    uses: loxchi-s/dorker-skills/.github/workflows/local-ai-workbench.yml@main
    with:
      prompt: "Review correctness, security, performance, and missing tests."
```

The reusable workflow checks out the caller repository, not this skills repository.
The caller must allow reusable workflows from `loxchi-s/dorker-skills` under its Actions
settings. For private repositories, confirm GitHub's reusable-workflow access policy.

## Resource profile

- Runner: GitHub-hosted `ubuntu-latest`; actual CPU/RAM allocation depends on GitHub plan.
- Ollama container: capped at 2 CPU cores, 4 GiB RAM, and 256 processes.
- Model: `qwen2.5:1.5b`; model weights are downloaded on each fresh runner unless a cache is
  added later. No GPU is requested.
- Job timeout: 25 minutes; Git diff context: 24,000 UTF-8 bytes; generation context: 4,096
  tokens; output: at most 768 tokens.
- Parallelism: one model job per workflow run. Repository-level concurrency cancels superseded
  runs for the same ref.

## Security boundaries

- `contents: read`; checkout does not persist credentials.
- No secrets are passed to the model container.
- Pull request content is treated as untrusted text; no PR code is executed by the model job.
- Common credential patterns and PEM private-key blocks are redacted before inference. This
  is best-effort redaction, not a guarantee; never commit secrets to a repository.
- The model container has bounded CPU, memory and process count. It requires network access
  to download the container image and model weights.
- The workflow uses a versioned container tag, not a digest pin. Pin a verified image digest
  before treating this as a hardened supply-chain deployment.
- No automatic retries for inference; rerun the failed workflow manually.

## Status

- Implemented in this branch: workflow, bounded local inference client, report artifact,
  reusable workflow contract, and unit tests.
- Not yet validated: real GitHub Actions execution, cold model download time, model quality,
  and reusable-workflow access from the `football` repository.
- Not a coding agent: it reviews diffs but does not edit source code or open pull requests.