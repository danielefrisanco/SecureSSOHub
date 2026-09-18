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

## 2026-09-18 — TASK-005 done: Remove OmniAuth client wiring from the hub
- Deleted the ssoprovider initializer, OmniauthCallbacksController, /auth/* routes and the Minitest asserting the strategy; dropped omniauth + omniauth-rails_csrf_protection from the default group. The app boots for the first time; rspec green (1 pending).
- Commits: 7302741 (refactor), task-file commits. Test DB: docker compose `db` + DATABASE_URL (database.yml host made env-configurable in TASK-006).
- Merged into develop. main is merged/pushed by the user.

## 2026-09-18 — TASK-002 done: Remove stray file, README transcript and TODO stub; add ARCHITECTURE.md
- `a` deleted; README rewritten; docs/ARCHITECTURE.md (purpose, roles, trust boundaries, decisions log). Commits 5063777 + fix. Merged into develop.

## 2026-09-18 — TASK-003 done: Record authorization-server core decision (Doorkeeper) in ARCHITECTURE.md
- docs/ARCHITECTURE.md §4: Doorkeeper + doorkeeper-openid_connect behind the service layer, own gem open; per-gem role table; decisions-log entry. Merged into develop.

## 2026-09-18 — TASK-006 done: Fix Devise schema and modules
- Migration adds encrypted_password, recoverable/confirmable/lockable columns, disabled_at; User modules trackable/lockable/timeoutable, registerable off; database.yml host via POSTGRES_HOST; factory + model + sign-in request specs (8 green). Commit a7116b2. Merged into develop.

## 2026-09-18 — TASK-007 done: Align User with jwt_auth_client 0.2.0 and add its initializer
- User#jwt_claims; initializer reads JWT_SERVICE_SECRET (no fallback, boot fails without it; skipped only under SECRET_KEY_BASE_DUMMY) and JWT_ISSUER; to_jwt specs (10 green). Commit 8ffa274. Merged into develop.

## 2026-09-18 — TASK-008 done: Delete Minitest suite, port cases to RSpec, complete test setup
- test/ removed; rails_helper (WebMock, Timecop safe mode, Devise helpers), spec_helper random order, :admin factory trait. Commit bbad4cd. Merged into develop.

## 2026-09-18 — TASK-009 done: Add landing page and styled Devise views
- HomeController, layout with header/flash, generated + styled Devise views, single stylesheet, hello_controller removed; 20 specs. Commit bb3311b. Merged into develop.

## 2026-09-18 — TASK-010 done: Mount header_guard with a nonce-aware CSP and security headers
- header_guard for HSTS/frame/nosniff/referrer/COOP/CORP/permissions; Rails CSP enforced with per-request nonce (header_guard 0.3.1 has no nonce support → T46). Specs verify nonce on every inline script. Commit b870b84. Merged into develop.

## 2026-09-18 — TASK-011 done: Add GitHub Actions CI, rubocop and security scanners
- ci.yml (rspec w/ Postgres, rubocop, brakeman --except EOL checks, bundler-audit non-blocking, docker build); .rubocop.yml + safe autocorrects; harness lint_command set. T30 (Ruby/Rails upgrade) raised to critical. Commit 90e371a. Merged into develop.
- Phase 0 complete (TASK-002..011). Next: TASK-012 Phase 0 gate. User must merge develop → main and push; first CI run happens then.

## 2026-09-18 — TASK-012 done: Phase 0 gate — verify outcomes, re-plan Phase 1 and create its tasks
- docs/PHASES.md: Phase 0 6/6 verified (CI only local — nothing pushed). Decisions: RS256 JWT access tokens via doorkeeper-jwt, Redis, approval-gated registration with policy switch, Ruby 3.4/Rails 8 upgrade first.
- Phase 1 = TASK-013..025 (detailed specs) + gate TASK-026; TODO.md and ARCHITECTURE.md updated. Merged into develop.
- Next: `/harness:start-task TASK-013` (upgrade). User must merge develop → main and push.

## 2026-09-18 — TASK-013 done: Upgrade Ruby to 3.4 and Rails to 8.x; make security scanners blocking
- Ruby 3.4.10, Rails 8.1.3.1 (load_defaults 8.1), Postgres 17 (new compose volume), Devise 5.0.4, Puma 7.2.1, json pinned 2.x (rack-session 2.1.2 vs json 3); unused Active Storage/Mailbox/Text engines removed; sassc-rails out, sprockets-rails explicit. brakeman 0 (no exclusions), bundler-audit clean, rubocop clean, rspec 23/0, docker build ok. Merged into develop.

## 2026-09-18 — TASK-014 done: Install Doorkeeper, doorkeeper-openid_connect and doorkeeper-jwt behind a service layer
- Gems + migrations; config verified against gem source (PKCE forced, hashed secrets, 10 min tokens, JWT generator); signing-key boot guard; OIDC issuer from HUB_ISSUER, subject = sso_id; app/services/oauth skeleton + isolation spec; 31 specs. Merged into develop.

## 2026-09-18 — TASK-015 done: Signing keys with kid and rotation, JWKS endpoint, dev key tooling
- OAuth::SigningKey (env PEM/base64, RFC 7638 kid, previous key for rotation, realm-ready accessor); ruby-jwt kid generator = Thumbprint; doorkeeper-jwt + openid_connect sign via it; JWKS at /.well-known/jwks.json and /oauth/discovery/keys with cache headers; hub:keys rake tasks; README runbook. 51 specs. Merged into develop.
- STOPPED HERE at the user's request (handoff + compact). Next: /harness:start-task TASK-016 (client registry). Reminder: develop → main merge/push is the user's step; local test runs need DATABASE_URL pointing at the compose Postgres 17 on localhost.
