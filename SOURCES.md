# Upstream Skill Sources

These repositories are discovery sources, not blanket approvals. A repository being public or popular does not make its contents trusted.

| Project | URL | Intended use | Review gate |
|---|---|---|---|
| Agent Skills specification | https://github.com/agentskills/agentskills | Portable `SKILL.md` format and interoperability rules | Verify the current specification before changing parsers |
| obra/superpowers | https://github.com/obra/superpowers | TDD, brainstorming, debugging, planning, subagent workflows | Review each skill, scripts, license and immutable revision |
| obra/superpowers-skills | https://github.com/obra/superpowers-skills | Community-maintained extensions for Superpowers | Treat community contributions as untrusted until reviewed |
| Anthropic skills | https://github.com/anthropics/skills | General-purpose, document, coding and workflow skills | Select individual skills; verify license and provenance |
| Vercel agent skills | https://github.com/vercel-labs/agent-skills | React, frontend, web design and performance engineering | Select individual skills; verify license and provenance |
| Trail of Bits skills | https://github.com/trailofbits/skills | Security auditing, secure development and code analysis | Mandatory security review; inspect scripts and external dependencies |
| GitHub Awesome Copilot | https://github.com/github/awesome-copilot | Agent instructions, prompts, custom agents and skills | Check each artifact's license, scope and tool assumptions |
| Supabase agent skills | https://github.com/supabase/agent-skills | Supabase, PostgreSQL and data-layer engineering | Verify SQL impact, permissions and license |
| Microsoft skills | https://github.com/microsoft/skills | Microsoft ecosystem and engineering workflows | Select relevant skills; verify license and provenance |
| Awesome Agent Skills index | https://github.com/heilcheng/awesome-agent-skills | Discovery index for skills from multiple engineering teams | Index only; always review the original upstream source |
| Skills directory | https://skills.sh/ | Popularity and discovery signals for published skills | Popularity is not a security or quality signal |\n| CrewAI | https://github.com/crewAIInc/crewAI | Multi-agent Crews and event-driven Flows | Review current API, tools, dependencies and license before adopting upstream code |\n| CrewAI Skills | https://github.com/crewAIInc/skills | Framework-specific agent development guidance | Review each skill and license; no verbatim import by default |\n| LangChain | https://github.com/langchain-ai/langchain | Model integrations, Runnables, retrieval and agent composition | Prefer current v1 APIs; inspect provider packages and license |

## Import policy

- Discovery does not imply approval, installation or runtime enablement.
- Record the exact upstream repository, path, commit SHA, license evidence and SHA-256 for every imported artifact.
- Review the complete skill and all referenced scripts/resources for prompt injection, secret access, network access, destructive operations and hidden dependencies.
- Prefer copying only the reviewed skill files; do not execute upstream install scripts.
- Keep imported candidates in `upstream-candidates.json` until individually reviewed and pinned.
- The registry remains `runtime_enabled: false`; no upstream skill is trusted by default.

No upstream skill is approved for execution by this source list.
