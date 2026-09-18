# SecureSSOHub — backlog

Derived from [`docs/AUDIT.md`](docs/AUDIT.md) (TASK-001, 2026-09-18). Ordered: work top to bottom;
"after" lists hard dependencies. Each item is sized for one harness task
(`/harness:create-task` with the line as the description).

Columns: **id · title · type · priority · placement · depends on · audit ref**.
Placement: `[app]` this repo · `[gem: x]` change in that gem · `[new gem]` extract a new gem.

**Phase gates.** Every phase ends with a gate task (type `docs`) that depends on all tasks of the
phase: it verifies the phase's end state against the audit, re-plans the *next* phase's rows against
the code as it actually is (split/merge/reorder/drop/add, ask blocking questions), creates one harness
task per row, annotates the rows with their task ids, and creates the next gate. Phase 0 gate: TASK-012,
Phase 1 gate: TASK-026. Verification records live in [`docs/PHASES.md`](docs/PHASES.md).
Only the current phase and its gate are ever instantiated as harness tasks; later phases stay as rows.
Gem rows (`[gem: x]`) are worked in the gem's own repository; a hub task only bumps the version.

## Phase 0 — foundations (make the app boot, decide the core) — DONE 2026-09-18

| id | title | type | prio | placement | after | ref |
|---|---|---|---|---|---|---|
| T01 (TASK-002) | Remove stray file `a`, README transcript and the TODO stub; add docs/ARCHITECTURE.md skeleton with the "licensing/tenancy is a separate service" note | chore | high | [app] | — | §4, §7 E4 |
| T02 (TASK-003) | Record the AS-core decision in docs/ARCHITECTURE.md: **Doorkeeper + doorkeeper-openid_connect now, own gem left open** — keep Doorkeeper behind the app's service layer so it can be swapped | docs | critical | [app] | — | §5.4, §10 Q1 |
| T03 (TASK-004) | Update Gemfile.lock to jwt_auth_client 0.2.0, rack-jwt-verifier 0.3.0, header_guard 0.3.1; drop omniauth_syncer; move omniauth-ssoprovider to the development/test group; make `bundle install` succeed | chore | critical | [app] | — | §3, §5.5 |
| T04 (TASK-005) | Remove the OmniAuth *client* wiring: omniauth_ssoprovider initializer, `/auth/*` routes, OmniauthCallbacksController, test/initializers spec; keep omniauth-rails_csrf_protection only if still needed | refactor | critical | [app] | T03 | §7 E5, §8 |
| T05 (TASK-006) | Fix Devise schema: migration adding `encrypted_password`, `reset_password_token`/`sent_at`, `confirmation_*`, `failed_attempts`/`unlock_token`/`locked_at`, `disabled_at`; enable `:trackable :lockable :timeoutable`; disable `:registerable` | fix | critical | [app] | T03 | §1 (3), §5.1 |
| T06 (TASK-007) | Rewrite `User` for jwt_auth_client 0.2.0: `#jwt_claims`, remove `jwt_payload`/`jwt_secret`; add `config/initializers/jwt_auth_client.rb` reading `JWT_SERVICE_SECRET`/`JWT_ISSUER` from env (no fallbacks); add model specs | fix | critical | [app] | T03 | §3.1 |
| T07 (TASK-008) | Delete `test/`, port its three cases to RSpec; extend `rails_helper` (FactoryBot syntax, Devise helpers, WebMock); real `users` factory | test | high | [app] | T05, T06 | §7 E3, §5.5 |
| T08 (TASK-009) | Add HomeController#index landing page (signed-out → sign-in CTA, signed-in → account link) and generate/style Devise views with a single minimal stylesheet; remove hello_controller.js | feat | high | [app] | T05 | §7 E1, §5.3 |
| T09 (TASK-010) | Mount header_guard with a nonce-aware CSP compatible with importmap/Turbo; delete the commented Rails CSP initializer; set Permissions-Policy; request specs asserting headers | feat | high | [app] | T03 | §7 E2, §3.5 |
| T10 (TASK-011) | GitHub Actions CI: bundle, db:prepare, rspec, rubocop, brakeman, bundler-audit, docker build; add rubocop config and `checks.lint_command` in harness.yaml | ci | high | [app] | T03, T07 | §5.5 |
| G0 (TASK-012) | Phase 0 gate — verify outcomes, re-plan Phase 1 and create its tasks | docs | high | [app] | T01–T10 | all |

## Phase 1 — authorization server core

Re-planned by the Phase 0 gate (TASK-012, 2026-09-18) around the decisions: Doorkeeper +
doorkeeper-openid_connect core, **RS256 JWT access tokens via doorkeeper-jwt**, Redis as the shared
cache (Phase 2), **approval-gated dynamic registration behind a policy switch**, and the Ruby/Rails
upgrade first. Every task keeps Doorkeeper behind `app/services/oauth/` (isolation spec, TASK-014).

| id | title | type | prio | placement | after | ref |
|---|---|---|---|---|---|---|
| T30 (TASK-013) | Upgrade Ruby → 3.4, Rails → 8.x (newest stable), Postgres image → 17; drop sassc-rails; make brakeman EOL checks and bundler-audit blocking in CI. *Moved here from Phase 2 (critical).* | chore | critical | [app] | — | §4, §10 Q5 |
| T47 (TASK-014) | Install Doorkeeper, doorkeeper-openid_connect, doorkeeper-jwt; base config (Devise authenticators, hashed secrets, flows, lifetimes, JWT generator); `app/services/oauth/` skeleton; architecture spec that no `Doorkeeper::` leaks outside it; smoke specs | feat | critical | [app] | T30 | §5.4, ARCHITECTURE §4 |
| T11 (TASK-015) | `SigningKey`: RSA keys from `OIDC_SIGNING_KEY`(+`_PREVIOUS`), RFC 7638 `kid`, production boot guard, ephemeral dev/test key; doorkeeper-jwt + openid_connect signing wired; `/.well-known/jwks.json` (+ `/oauth/discovery/keys`) with Cache-Control/ETag; `hub:keys:*` rake tasks; rotation runbook | feat | critical | [app] | T47 | §5.1, §5.2, §6.3 |
| T13 (TASK-016) | Client registry on `Doorkeeper::Application`: client_type, approval_state, registered_via, owner, RFC 7591 metadata, last_used_at; `OAuth::ClientRules` (URI allow-list, scope subset, transitions); `OAuth::Clients` service (create w/ one-time secret, rotate, approve, revoke, admin-only); factory | feat | critical | [app] | T47 | §5.1, §6.3 |
| T14 (TASK-017) | `/oauth/authorize` hardening: S256 PKCE mandatory for public clients, exact redirect_uri (never redirect on mismatch), `state`, RFC 8707 `resource` → `OAuth::Resources` + grant/token columns, pending/revoked clients and disabled users refused, `response_type=code` only, RFC 6749 errors; negative specs | feat | critical | [app] | T13 | §5.4 |
| T15 (TASK-018) | `OAuth::Scopes` catalogue with user-facing descriptions (admin-only scopes), `oauth_consents` + `OAuth::Consents` (covers?/grant/revoke), Doorkeeper `skip_authorization`, restyled consent page under the CSP; escalation/revocation re-ask specs | feat | high | [app] | T14 | §5.3, §6.3 |
| T16 (TASK-019) | `/oauth/token`: JWT payload builder (iss, sub=sso_id, aud=resource∣client, azp, scope+scopes, jti, exp 10 min, scope-gated name/email, admin), refresh tokens only with `offline_access`, rotation + reuse → family revocation, id_token (nonce/auth_time/at_hash), client auth rules, code replay revocation, last_used_at; remove legacy jwt_auth_client wiring; document payload | feat | critical | [app] | T11, T14 | §5.4, §6.3 |
| T17 (TASK-020) | `/api/v1/userinfo` (omniauth-ssoprovider contract) + `/oauth/userinfo` (OIDC); `/api/**` behind rack-jwt-verifier with in-process key source, `iss` + hub-API `aud`, revoked/disabled checks; interop spec with the gem in JWKS mode; gem limitations → rows below | feat | critical | [app] | T16 | §3.2, §3.3, §5.4 |
| T18 (TASK-021) | Discovery: complete `/.well-known/openid-configuration` + RFC 8414 `/.well-known/oauth-authorization-server` from one `OAuth::Metadata` builder (URLs from `HUB_ISSUER`, not Host), cache headers, CORS for discovery/jwks only | feat | high | [app] | T16 | §5.4 |
| T19 (TASK-022) | `/oauth/revoke` (RFC 7009) + `/oauth/introspect` (RFC 7662, `introspect` scope); `OAuth::Tokens` revoke / revoke_all_for(user) / revoke_for(user, client) / revoke_all_for_client / active_for; password change + admin disable revoke everything; JWT revocation trade-off documented | feat | high | [app] | T16 | §5.4, §6.3 |
| T20 (TASK-023) | End-to-end specs: a Rack "client app" with the real omniauth-ssoprovider strategy (mounted by class, see T44) completes PKCE login against the in-process hub via WebMock `to_rack`; negatives (state, denied consent, pending client); rack-jwt-verifier standalone app accepts the token, rejects wrong aud/scope, survives key rotation | test | critical | [app] | T17, T18 | §5.5 |
| T21 (TASK-024) | Machine token grant (RFC 6749 §4.4) for confidential approved clients: per-client machine scope allow-list, sub=azp=client uid, no user claims/refresh, `resource` supported; via `OAuth::Tokens.issue_client_token` | feat | medium | [app] | T16 | §6.2 |
| T22 (TASK-025) | Dynamic client registration `POST /oauth/register` (RFC 7591) on `OAuth::Clients`; `OAUTH_REGISTRATION_POLICY` approval (default) ∣ open ∣ closed; pending until admin approval; never admin/machine scopes; per-IP cap + duplicate guard; discovery advertises the endpoint | feat | medium | [app] | T13, T18 | §5.4, §10 Q4 |
| G1 (TASK-026) | Phase 1 gate — verify outcomes, re-plan Phase 2 and create its tasks | docs | high | [app] | all of Phase 1 | all |
| T12 | jwt_auth_client 0.3.0: asymmetric signing (RS256/ES256) with `kid` header, JWKS publisher helper. *Deferred by the gate: with doorkeeper-jwt + `SigningKey` the hub's OAuth tokens no longer go through jwt_auth_client; needed only when hub→service calls (`HttpClient`) should verify against the same JWKS.* | feat | low | [gem: jwt_auth_client] | T11 | §3.1, §9 |

## Phase 2 — security hardening & operations

| id | title | type | prio | placement | after | ref |
|---|---|---|---|---|---|---|
| T23 | **Redis** (decided) as `Rails.cache` + compose service; enable rack-jwt-verifier `replay_cache` on `/api` and `/mcp`; authorization-code single-use via cache/DB | feat | high | [app] | T17 | §5.2, §10 Q2 |
| T24 | Rate limiting (rack-attack or equivalent) on `/oauth/token`, sign-in, password reset, `/oauth/register` (replaces the DB cap from TASK-025); specs | feat | high | [app] | T23 | §5.1 |
| T25 | Audit log table + service (sign-in, grant, token issue/revoke, admin actions, MCP tool calls) with `azp`/client attribution; hook points already exist in `OAuth::Clients`/`OAuth::Tokens`; specs | feat | high | [app] | T16 | §5.1, §6.3 |
| T26 | Devise hardening: password length ≥ 12 + pwned-password check, `:confirmable` with a real mailer config, `mailer_sender`; specs | feat | medium | [app] | T05, T10 | §5.1, §10 Q3 |
| T27 | TOTP 2FA for admins (enrolment UI + sign-in step); specs | feat | medium | [app] | T26 | §5.1 |
| T28 | rack-cors full policy (discovery/jwks done in TASK-021): token/userinfo/MCP endpoints; specs | feat | medium | [app] | T17 | §5.1 |
| T29 | Production deployment: `docker-compose.prod.yml` (web, db, redis, TLS-terminating proxy), env-only configuration, remove hardcoded dev DB password from the dev compose, readiness endpoint (DB + cache + signing key), JSON request logs | chore | high | [app] | T23 | §5.2, §4 |

## Phase 3 — user, admin and developer UI

| id | title | type | prio | placement | after | ref |
|---|---|---|---|---|---|---|
| T31 | Account page: profile edit, password change, connected apps with per-grant revoke, active sessions with "sign out everywhere"; system specs | feat | high | [app] | T15, T19 | §5.3 |
| T32 | Admin: OAuth clients CRUD with one-time client-key display and rotation, approval of pending registrations | feat | high | [app] | T13, T22 | §5.3 |
| T33 | Admin: users list/search/disable/promote; tokens & grants view with revoke | feat | high | [app] | T19 | §5.3 |
| T34 | Admin: audit log viewer with filters | feat | medium | [app] | T25 | §5.3 |
| T35 | Developer page: generated omniauth-ssoprovider initializer and rack-jwt-verifier snippet per client | feat | medium | [app] | T18 | §5.3 |
| T36 | Error pages, flash styling, accessibility pass (labels, focus, contrast) over all views | feat | low | [app] | T31–T35 | §5.3 |

## Phase 4 — MCP endpoint (agents)

| id | title | type | prio | placement | after | ref |
|---|---|---|---|---|---|---|
| T37 | Service-object layer shared by controllers and MCP tools (clients, users, grants, tokens, sessions, audit) so authorization/validation/audit live once — `app/services/oauth/` from Phase 1 is the seed | refactor | high | [app] | T31–T34 | §6.1 |
| T38 | MCP server endpoint `POST /mcp` (Streamable HTTP) using the official Ruby `mcp` gem; `initialize`, `tools/list`; specs | feat | high | [app] | T37 | §6 |
| T39 | MCP authorization glue: rack-jwt-verifier on `/mcp` (`aud` = MCP resource, per-tool `require_scopes`), RFC 9728 `/.well-known/oauth-protected-resource`, `WWW-Authenticate … resource_metadata` challenge; end-to-end spec of an agent obtaining a token via the hub (dynamic registration → approval → PKCE) | feat | critical | [app] → candidate [new gem] `rack-mcp-auth` | T18, T22, T38 | §6.2, §6.3 |
| T40 | rack-jwt-verifier: optional `resource_metadata` in the `WWW-Authenticate` challenge and a `current_token` helper (if T39 shows it is generic) | feat | medium | [gem: rack-jwt-verifier] | T39 | §3.2, §9 |
| T41 | MCP user tools: `whoami`, `get_profile`, `update_profile`, `list_grants`, `revoke_grant`, `list_sessions`, `revoke_sessions`, `integration_snippet`; specs | feat | high | [app] | T39 | §6.1 |
| T42 | MCP admin tools: clients CRUD + rotate + approve, users list/get/disable/set_admin, tokens list/revoke, `search_audit_log`, `introspect_token`; MCP resources for discovery/JWKS/clients; specs | feat | high | [app] | T41 | §6.1 |
| T43 | Agent onboarding docs: how an MCP client registers, authorizes and calls the hub (in docs/ and the developer page) | docs | medium | [app] | T42 | §6 |

## Gem follow-ups (other repos, not blocking the hub)

| id | title | type | prio | placement | after | ref |
|---|---|---|---|---|---|---|
| T44 | omniauth-ssoprovider: fix `:ssoprovider` name lookup (`OmniAuth.config.add_camelization`), `pkce: true` default, `id_token` handling, `state`/return-to docs, expose `roles`, add a spec suite; release and bump | fix | high | [gem: omniauth-ssoprovider] | — | §3.3, §9 |
| T45 | omniauth_syncer: require the engine properly or drop it; add a spec suite | fix | low | [gem: omniauth_syncer] | — | §3.4, §9 |
| T46 | header_guard: Rails CSP nonce integration helper (needed since TASK-010 keeps the CSP in Rails) | feat | low | [gem: header_guard] | T09 | §3.5, §9 |
| T48 | rack-jwt-verifier: accept an in-process / callable JWKS or key-set source (hub verifying its own tokens without HTTP — TASK-020 will confirm whether `public_key` suffices) | feat | medium | [gem: rack-jwt-verifier] | T17 | §3.2 |
