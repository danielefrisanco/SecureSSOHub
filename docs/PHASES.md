# Phase records

Each phase gate (see `TODO.md` "Phase gates") records here what was verified, with evidence, and
what was re-planned for the next phase. Newest phase last.

## Phase 0 — foundations (gate TASK-012, 2026-09-18)

Tasks TASK-002 … TASK-011, all reviewed PASS and merged into `develop`.

| # | Check (from the gate task) | Result | Evidence |
|---|---|---|---|
| 1 | App boots | pass | `RAILS_ENV=test bin/rails runner` → `booted test rails 7.1.5.2` |
| 2 | `bundle exec rspec` green | pass | `23 examples, 0 failures`, `Randomized with seed 8122` (run twice) |
| 3 | CI green | pass locally / **not yet on GitHub** | rubocop `40 files inspected, no offenses`; brakeman `No warnings found` (EOL checks excluded, see below); `.github/workflows/ci.yml` present; nothing has been pushed, so no Actions run exists yet |
| 4 | Devise sign-in works | pass | integration session `POST /users/sign_in` → `303 → /`; `sign_in_count` incremented (sessions_spec) |
| 5 | header_guard headers present | pass | `strict-transport-security`, `x-frame-options: DENY`, `x-content-type-options: nosniff`, `referrer-policy`, `permissions-policy`, COOP/CORP on `/`; CSP with a per-request nonce on `script-src` |
| 6 | Landing page renders | pass | `GET /` → 200; signed-in greeting rendered ("Hello, Gate") |

Deviations from the audit / things learned
- header_guard 0.3.1 cannot express a per-request CSP nonce; the CSP stays with Rails (nonce),
  header_guard sends the other headers. Gem follow-up T46.
- omniauth-ssoprovider 0.1.2 does not register a camelization for `:ssoprovider`; its README example
  does not boot. Gem follow-up T44; the E2E spec (TASK-023) mounts the strategy by class.
- brakeman reports Ruby 3.1.4 and Rails 7.1.5.2 as EOL; bundler-audit lists ~75 advisories, most in
  Rails 7.1.5.2 → the upgrade (T30) moved to the top of Phase 1 as TASK-013; until it lands CI
  excludes the two EOL checks and runs bundler-audit non-blocking.
- The compose `db` container was destroyed/recreated twice during the day by something outside the
  sessions (Docker events); the named volume kept the data.

Decisions taken at this gate (details in `docs/ARCHITECTURE.md` §5)
- Access tokens: RS256 JWTs via doorkeeper-jwt, signed by the hub's `SigningKey`; id_tokens via
  doorkeeper-openid_connect. `rack-jwt-verifier` is the verifier everywhere; `jwt_auth_client`
  leaves the OAuth path (T12 deferred).
- Shared cache: Redis.
- Dynamic client registration: approval-gated by default, `OAUTH_REGISTRATION_POLICY` switch for a
  future open mode.
- Ruby 3.4 / Rails 8.x upgrade first (TASK-013).

Phase 1 plan: 13 tasks TASK-013 … TASK-025 plus the Phase 1 gate TASK-026 (see `TODO.md`).
