# GitHub Local AI Workbench

A GitHub Actions-native, CPU-only local-model reviewer. It uses an ephemeral GitHub-hosted
Ubuntu runner and a versioned Ollama container; no external AI API key is required.

## Current scope

- Manual run (workflow_dispatch) with an optional review prompt.
- Pull-request review (pull_request) with read-only repository permissions.
- Reusable workflow (workflow_call) so another repository can call this workflow.
- Qwen 2.5 1.5B through Ollama, downloaded at run time and executed locally on CPU.
- Bounded Git diff context, common-secret redaction, timeout, and a Markdown artifact.
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
      prompt: "Review correctness, security, performance, and missing tests."
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
- Job timeout: 25 minutes; Git diff context: 24,000 UTF-8 bytes; generation context: 4,096
  tokens; output: at most 768 tokens.
- Parallelism: one model job per workflow run. Repository-level concurrency cancels superseded
  runs for the same ref.

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
- The workflow uses a versioned container tag, not a digest pin. Pin a verified image digest
  before treating this as a hardened supply-chain deployment.
- Reports are written to the runner's temporary directory, never to a pre-existing file in the
  caller checkout. Missing reports are ignored on upload.
- No automatic retries for inference; rerun the failed workflow manually.

## Status

- Implemented in this branch: workflow, bounded local inference client, report artifact,
  reusable workflow contract, and unit tests.
- The in-repository GitHub Actions path has successful evidence on the current PR head.
- Not yet validated: external reusable-workflow invocation from the football repository,
  cold model download time, and model quality.
- Not a coding agent: it reviews diffs but does not edit source code or open pull requests.
