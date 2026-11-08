---
name: skill-registry
description: Discovers, versions, validates and manages Dorker skills from Git repositories. Use when adding, updating, pinning, reviewing or retiring a skill.
---
# Skill Registry
1. Validate catalog, skill directory and required frontmatter.
2. Record upstream URL, immutable commit, license, retrieval date and content hashes.
3. Inspect every file, script and dependency; reject unexpected binaries and install hooks.
4. Validate references and scripts; run static checks.
5. Pin approved version and retain rollback metadata.
6. Keep discovery, installation, testing and runtime enablement as separate states.
