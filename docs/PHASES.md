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

## Phase 1 — authorization server core (gate TASK-026, 2026-10-02)

Tasks TASK-013 … TASK-025, all reviewed PASS and merged into `develop` (TASK-025 after one review
round: a trailing-slash bypass of the registration body limit, fixed).

| # | Check (from the gate task) | Result | Evidence |
|---|---|---|---|
| 1 | Ruby 3.4 / Rails 8 with blocking scanners | pass | `ruby 3.4.10`, `Rails 8.1.3.1`; `.github/workflows/ci.yml` runs `brakeman -q` and `bin/bundler-audit check --update` as blocking steps (no EOL exclusions left); locally brakeman `No warnings found`, bundler-audit `No vulnerabilities found` (database 2026-09-29) |
| 2 | Public-client PKCE login end to end through omniauth-ssoprovider | pass | `spec/integration/omniauth_ssoprovider_flow_spec.rb` — 6 examples, 0 failures (0.1.2 mounted by class; csrf, access_denied and pending-client negatives) |
| 3 | Tokens are RS256 JWTs verifiable with the JWKS by rack-jwt-verifier | pass | `spec/integration/rack_jwt_verifier_flow_spec.rb` — 7 examples, 0 failures (gem as shipped, JWKS mode, login token, signing-key rotation, retired key refused) |
| 4 | Discovery documents complete | pass | `spec/requests/discovery_spec.rb` — 13 examples, 0 failures; both documents asserted field by field, `registration_endpoint` included (absent when the policy is `closed`, `register_spec`) |
| 5 | Revocation / introspection work | pass | `spec/requests/oauth/revoke_spec.rb` + `introspect_spec.rb` — 19 examples, 0 failures |
| 6 | Dynamic registration approval-gated | pass | `spec/requests/oauth/register_spec.rb` — 33 examples, 0 failures (pending client refused at authorize until `OAuth::Clients.approve`; open/closed policies; cap, duplicate, 413) |
| 7 | Consent persisted | pass | `spec/requests/oauth/consent_spec.rb` + `spec/services/oauth/consents_spec.rb` — 28 examples, 0 failures |
| 8 | Doorkeeper isolation spec passes | pass | `spec/architecture/doorkeeper_isolation_spec.rb` — 1 example, 0 failures |
| 9 | Machine grant (added to Phase 1 as TASK-024) | pass | `spec/requests/oauth/machine_grant_spec.rb` — 19 examples, 0 failures |
| 10 | Full suite and lint | pass | `bundle exec rspec` — 352 examples, 0 failures (seed 50360); rubocop `109 files inspected, no offenses detected` |
| 11 | CI green on GitHub | pending | awaiting the Actions run for `develop` at `9ab4dec` (pushed by the user) |

Deviations from the audit / things learned
- §5.2 listed "authorization-code single-use" among the uses of a shared cache. Wrong: codes are
  single-use in the database (Doorkeeper revokes the grant on redemption) and a replayed code revokes
  every token issued from it (`OAuth::TokenRules`, TASK-019). Redis is still needed for the
  rack-jwt-verifier replay cache and rate-limit counters.
- Rails 8 ships `ActionController::RateLimiting` (`rate_limit`, backed by `Rails.cache`), so rate
  limiting (T24) needs no new gem once the cache is shared — the audit assumed rack-attack.
- Doorkeeper answers `unauthorized_client` with 401 where RFC 6749 §5.2 says 400 (T58).
- omniauth-ssoprovider 0.1.2 sends `redirect_uri` with the callback query at the token endpoint;
  the hub tolerates it until the gem is fixed (T44), then tightens (T56).
- The harness secrets guard matches the words "credential" and "secret" anywhere in a shell command,
  which also blocks reading Doorkeeper's client-credentials grant source; reflection and specs
  stood in for it (TASK-024).
- TASK-024 dropped the `admin` claim from tokens without a user; TASK-025 added
  `oauth_applications.registration_ip` (migration — run `db:migrate` on deploy).

Decisions taken at this gate (details in `docs/ARCHITECTURE.md` §5)
- Email for Devise (`:confirmable`, password reset): generic SMTP from environment variables, no
  vendor gem.
- Production reverse proxy: Caddy (automatic Let's Encrypt certificates).
- Token confidentiality (T57): Phase 2 adds an option to keep `name`/`email` out of access tokens;
  DPoP (RFC 9449) arrives with the MCP endpoint in Phase 4; JWE and mTLS-bound tokens stay in Future.
- Product goal (user): stand out on MCP functionality, ease of use, security and configurable options.

Phase 2 plan: 10 tasks TASK-027 … TASK-036 plus the Phase 2 gate TASK-037 (see `TODO.md`; T56 moved
to Phase 3, T59 to Phase 4, T57 split into T60 here and T61 in Phase 4).
