# SecureSSOHub

## Harness

This project uses the **harness** plugin for task-driven development.

- Config: `harness.yaml` · rules: `.harness/rules/*.md` (read them before non-trivial work) · tasks: `tasks/`
- Workflow: `/harness:create-task` → `/harness:refine-task` → `/harness:start-task` → work → `/harness:commit` → `/harness:complete-task`
- Never read secrets or git-ignored files. Never push. Never commit on protected branches.
- When something is unclear, ask with AskUserQuestion instead of guessing.
- Before ending a session with work in progress, run `/harness:handoff`.
