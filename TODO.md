# SecureSSOHub — backlog

Derived from [`docs/AUDIT.md`](docs/AUDIT.md) (TASK-001, 2026-09-18). Ordered: work top to bottom;
"after" lists hard dependencies. Each item is sized for one harness task
(`/harness:create-task` with the line as the description).

Columns: **id · title · type · priority · placement · depends on · audit ref**.
Placement: `[app]` this repo · `[gem: x]` change in that gem · `[new gem]` extract a new gem.

## Phase 0 — foundations (make the app boot, decide the core)

| id | title | type | prio | placement | after | ref |
|---|---|---|---|---|---|---|
| T01 | Remove stray file `a`, README transcript and the TODO stub; add docs/ARCHITECTURE.md skeleton with the "licensing/tenancy is a separate service" note | chore | high | [app] | — | §4, §7 E4 |
| T02 | Record the AS-core decision in docs/ARCHITECTURE.md: **Doorkeeper + doorkeeper-openid_connect now, own gem left open** — keep Doorkeeper behind the app's service layer so it can be swapped | docs | critical | [app] | — | §5.4, §10 Q1 |
| T03 | Update Gemfile.lock to jwt_auth_client 0.2.0, rack-jwt-verifier 0.3.0, header_guard 0.3.1; drop omniauth_syncer; move omniauth-ssoprovider to the development/test group; make `bundle install` succeed | chore | critical | [app] | — | §3, §5.5 |
| T04 | Remove the OmniAuth *client* wiring: omniauth_ssoprovider initializer, `/auth/*` routes, OmniauthCallbacksController, test/initializers spec; keep omniauth-rails_csrf_protection only if still needed | refactor | critical | [app] | T03 | §7 E5, §8 |
| T05 | Fix Devise schema: migration adding `encrypted_password`, `reset_password_token`/`sent_at`, `confirmation_*`, `failed_attempts`/`unlock_token`/`locked_at`, `disabled_at`; enable `:trackable :lockable :timeoutable`; disable `:registerable` | fix | critical | [app] | T03 | §1 (3), §5.1 |
| T06 | Rewrite `User` for jwt_auth_client 0.2.0: `#jwt_claims`, remove `jwt_payload`/`jwt_secret`; add `config/initializers/jwt_auth_client.rb` reading `JWT_SERVICE_SECRET`/`JWT_ISSUER` from env (no fallbacks); add model specs | fix | critical | [app] | T03 | §3.1 |
| T07 | Delete `test/`, port its three cases to RSpec; extend `rails_helper` (FactoryBot syntax, Devise helpers, WebMock); real `users` factory | test | high | [app] | T05, T06 | §7 E3, §5.5 |
| T08 | Add HomeController#index landing page (signed-out → sign-in CTA, signed-in → account link) and generate/style Devise views with a single minimal stylesheet; remove hello_controller.js | feat | high | [app] | T05 | §7 E1, §5.3 |
| T09 | Mount header_guard with a nonce-aware CSP compatible with importmap/Turbo; delete the commented Rails CSP initializer; set Permissions-Policy; request specs asserting headers | feat | high | [app] | T03 | §7 E2, §3.5 |
| T10 | GitHub Actions CI: bundle, db:prepare, rspec, rubocop, brakeman, bundler-audit, docker build; add rubocop config and `checks.lint_command` in harness.yaml | ci | high | [app] | T03, T07 | §5.5 |

## Phase 1 — authorization server core

| id | title | type | prio | placement | after | ref |
|---|---|---|---|---|---|---|
| T11 | Signing keys: generate/rotate RS256 (or ES256) key pairs from env/KMS, `kid` support, `GET /.well-known/jwks.json` with Cache-Control/ETag; specs | feat | critical | [app] | T02 | §5.1, §5.2, §6.3 |
| T12 | jwt_auth_client 0.3.0: asymmetric signing (RS256/ES256) with `kid` header, JWKS publisher helper; release and bump in the hub | feat | high | [gem: jwt_auth_client] | T11 | §3.1, §9 |
| T13 | OAuth client registry: `oauth_clients` (name, client_id, hashed client key, client_type public/confidential, redirect_uris exact-match, allowed scopes, dynamic/approved flags); admin-only model + service objects + specs | feat | critical | [app] | T02, T05 | §5.1, §6.3 |
| T14 | `GET /oauth/authorize`: authorization-code + PKCE (S256 mandatory for public clients), redirect_uri allow-list, `state`, `resource` indicator, RFC 6749 error responses; specs incl. negative cases | feat | critical | [app] | T13 | §5.4 |
| T15 | Consent screen and persisted consents per (user, client, scopes); skip on repeat; specs | feat | high | [app] | T14 | §5.3, §6.3 |
| T16 | `POST /oauth/token`: code exchange → JWT access token (`iss aud sub scopes azp jti exp`, RS256 via T11) + rotating refresh token (hashed, family revocation) + `id_token`; client auth; specs | feat | critical | [app] | T14 | §5.4, §6.3 |
| T17 | `GET /api/v1/userinfo` (bearer, via rack-jwt-verifier JWKS mode, `aud` = hub API) returning `{id, sub, name, email, roles}` matching omniauth-ssoprovider; specs | feat | critical | [app] | T16 | §3.2, §3.3, §5.4 |
| T18 | Discovery: `/.well-known/openid-configuration` and `/.well-known/oauth-authorization-server` (RFC 8414); specs | feat | high | [app] | T16 | §5.4 |
| T19 | `POST /oauth/revoke` (RFC 7009) and `POST /oauth/introspect` (RFC 7662); token/grant persistence needed for admin and "sign out everywhere"; specs | feat | high | [app] | T16 | §5.4, §6.3 |
| T20 | End-to-end spec: mount omniauth-ssoprovider as a client inside the test suite and complete sign-in → consent → token → userinfo against the hub; plus a spec that rack-jwt-verifier (jwks_url) accepts the hub's tokens | test | critical | [app] | T17, T18 | §5.5 |
| T21 | Client-credentials grant for machine clients (`sub = client_id`, restricted scopes); specs | feat | medium | [app] | T16 | §6.2 |
| T22 | Dynamic client registration `POST /oauth/register` (RFC 7591), approval-gated or rate-limited per decision; specs | feat | medium | [app] | T13 | §5.4, §10 Q4 |

## Phase 2 — security hardening & operations

| id | title | type | prio | placement | after | ref |
|---|---|---|---|---|---|---|
| T23 | Shared cache (Redis or Solid Cache — decide) as `Rails.cache`; enable rack-jwt-verifier `replay_cache` on `/api` and `/mcp`; authorization-code single-use via cache/DB | feat | high | [app] | T17 | §5.2, §10 Q2 |
| T24 | Rate limiting (rack-attack or equivalent) on `/oauth/token`, sign-in, password reset, `/oauth/register`; specs | feat | high | [app] | T23 | §5.1 |
| T25 | Audit log table + service (sign-in, grant, token issue/revoke, admin actions, MCP tool calls) with `azp`/client attribution; specs | feat | high | [app] | T16 | §5.1, §6.3 |
| T26 | Devise hardening: password length ≥ 12 + pwned-password check, `:confirmable` with a real mailer config, `mailer_sender`; specs | feat | medium | [app] | T05, T10 | §5.1, §10 Q3 |
| T27 | TOTP 2FA for admins (enrolment UI + sign-in step); specs | feat | medium | [app] | T26 | §5.1 |
| T28 | rack-cors initializer restricted to token/userinfo/MCP endpoints; specs | feat | medium | [app] | T17 | §5.1 |
| T29 | Production deployment: `docker-compose.prod.yml` (web, db, cache, TLS-terminating proxy), env-only configuration, remove hardcoded dev DB password from the dev compose, readiness endpoint (DB + cache + signing key), JSON request logs | chore | high | [app] | T23 | §5.2, §4 |
| T30 | Upgrade Ruby (≥ 3.3) and Rails (≥ 7.2/8.0) and Postgres image; run the suite | chore | medium | [app] | T10 | §4, §10 Q5 |

## Phase 3 — user, admin and developer UI

| id | title | type | prio | placement | after | ref |
|---|---|---|---|---|---|---|
| T31 | Account page: profile edit, password change, connected apps with per-grant revoke, active sessions with "sign out everywhere"; system specs | feat | high | [app] | T15, T19 | §5.3 |
| T32 | Admin: OAuth clients CRUD with one-time client-key display and rotation | feat | high | [app] | T13 | §5.3 |
| T33 | Admin: users list/search/disable/promote; tokens & grants view with revoke | feat | high | [app] | T19 | §5.3 |
| T34 | Admin: audit log viewer with filters | feat | medium | [app] | T25 | §5.3 |
| T35 | Developer page: generated omniauth-ssoprovider initializer and rack-jwt-verifier snippet per client | feat | medium | [app] | T18 | §5.3 |
| T36 | Error pages, flash styling, accessibility pass (labels, focus, contrast) over all views | feat | low | [app] | T31–T35 | §5.3 |

## Phase 4 — MCP endpoint (agents)

| id | title | type | prio | placement | after | ref |
|---|---|---|---|---|---|---|
| T37 | Service-object layer shared by controllers and MCP tools (clients, users, grants, tokens, sessions, audit) so authorization/validation/audit live once | refactor | high | [app] | T31–T34 | §6.1 |
| T38 | MCP server endpoint `POST /mcp` (Streamable HTTP) using the official Ruby `mcp` gem; `initialize`, `tools/list`; specs | feat | high | [app] | T37 | §6 |
| T39 | MCP authorization glue: rack-jwt-verifier on `/mcp` (`aud` = MCP resource, per-tool `require_scopes`), RFC 9728 `/.well-known/oauth-protected-resource`, `WWW-Authenticate … resource_metadata` challenge; end-to-end spec of an agent obtaining a token via the hub | feat | critical | [app] → candidate [new gem] `rack-mcp-auth` | T18, T22, T38 | §6.2, §6.3 |
| T40 | rack-jwt-verifier: optional `resource_metadata` in the `WWW-Authenticate` challenge and a `current_token` helper (if T39 shows it is generic) | feat | medium | [gem: rack-jwt-verifier] | T39 | §3.2, §9 |
| T41 | MCP user tools: `whoami`, `get_profile`, `update_profile`, `list_grants`, `revoke_grant`, `list_sessions`, `revoke_sessions`, `integration_snippet`; specs | feat | high | [app] | T39 | §6.1 |
| T42 | MCP admin tools: clients CRUD + rotate, users list/get/disable/set_admin, tokens list/revoke, `search_audit_log`, `introspect_token`; MCP resources for discovery/JWKS/clients; specs | feat | high | [app] | T41 | §6.1 |
| T43 | Agent onboarding docs: how an MCP client registers, authorizes and calls the hub (in docs/ and the developer page) | docs | medium | [app] | T42 | §6 |

## Gem follow-ups (other repos, not blocking the hub)

| id | title | type | prio | placement | after | ref |
|---|---|---|---|---|---|---|
| T44 | omniauth-ssoprovider: fix `:ssoprovider` name lookup (`OmniAuth.config.add_camelization`), `pkce: true` default, `id_token` handling, `state`/return-to docs, expose `roles`, add a spec suite; release and bump | fix | high | [gem: omniauth-ssoprovider] | — | §3.3, §9 |
| T45 | omniauth_syncer: require the engine properly or drop it; add a spec suite | fix | low | [gem: omniauth_syncer] | — | §3.4, §9 |
| T46 | header_guard: Rails CSP nonce integration helper | feat | low | [gem: header_guard] | T09 | §3.5, §9 |
