# Progress log

Append-only. Newest entry at the bottom. Written by `/harness:handoff` and `/harness:complete-task`.

## 2026-09-18 — TASK-001 done: Audit SSO hub codebase and write a production-readiness TODO plan
- docs/AUDIT.md: 5-gem inventory (versions, bundle show paths, usage, gaps), per-area Current→Desired→Gap, MCP + agent-auth design (hub as OAuth 2.1 AS for MCP clients), E1–E5 findings, rollups, gem follow-ups. Decision: Doorkeeper now, own gem left open.
- TODO.md: 46-item ordered backlog (T01–T46) with type/priority/placement/deps/audit refs; Phase 0 created as TASK-002..TASK-011.
- Commits on task/001-audit-sso-hub-codebase-and-write-a-produ: b822933 fe241e7 88b9b22 1d510a3 701095d b839e7e 9837d5e fb6a301 (+ completion). Gemfile.lock one-line sync approved as criterion-7 exception.
- Test gate waived: bundle exec rspec fails at boot on the pre-existing omniauth-ssoprovider LoadError (TASK-005 removes it; T44 fixes the gem). User must merge/push the branch to main.

## 2026-09-18 — TASK-004 done: Update gem lock, drop unused gems, make bundle install succeed
- Gemfile/Gemfile.lock: jwt_auth_client 0.2.0, rack-jwt-verifier 0.3.0, header_guard 0.3.1; omniauth_syncer removed; omniauth-oauth2 + omniauth-ssoprovider moved to development/test.
- Commits on task/004-update-gem-lock-drop-unused-gems-make-bu: 3238adc 5e5ddee f7c6878 (+ completion).
- App still fails to boot on the pre-existing omniauth-ssoprovider LoadError (TASK-005 removes the initializer); test gate waived. User must merge/push.
