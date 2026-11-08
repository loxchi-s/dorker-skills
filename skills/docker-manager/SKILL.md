---
name: docker-manager
description: Reviews and operates container builds and local container workloads. Use when a task requires Dockerfiles, Compose, image inspection or container lifecycle management.
---
# Docker Manager

## Workflow
1. Inspect Dockerfile, Compose files, image provenance and exposed ports.
2. Prefer minimal pinned base images and multi-stage builds.
3. Run as non-root; drop capabilities and use read-only filesystems where possible.
4. Set CPU, memory, PID and storage limits.
5. Scan images and dependencies before release.

## Safety
Do not build or run privileged containers, mount the host Docker socket or publish ports without explicit approval.
