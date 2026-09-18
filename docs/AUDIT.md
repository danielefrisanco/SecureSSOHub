# SecureSSOHub — production-readiness audit

Date: 2026-09-18 · Task: TASK-001 · Scope: `main` at `f7e1d6f` plus the five self-developed gems.
This document records *what exists*, *what it should be* and *the gap*; it changes no code.
The actionable backlog derived from it is in [`TODO.md`](../TODO.md).

Placement tags used throughout: `[app]` = belongs in this Rails app · `[gem: name]` = belongs in
one of the existing gems · `[new gem]` = generic enough to be extracted into a new gem.

---

## 1. Executive summary

SecureSSOHub is a Rails 7.1 skeleton (one model, one controller, one migration, no views beyond the
layout) that *intends* to be a JWT-issuing SSO hub. Today it cannot serve that purpose:

1. **It is wired as an SSO *client*, not a *provider*.** `config/initializers/omniauth_ssoprovider.rb`
   installs `omniauth-ssoprovider`, a consumer strategy that redirects users *to* an external hub at
   `/oauth/authorize` and `/oauth/token`. No provider-side endpoints exist in this app. The only
   controller expects auth-hash fields (`extra.return_to`) the strategy never produces.
2. **Token issuance is broken under either resolvable gem version.** `Gemfile.lock` pins
   `jwt_auth_client 0.1.0`, which has no `Issuable` module (`User` raises `NameError` at load). The
   published 0.2.0 has `Issuable` but requires `#jwt_claims` and a validated `JwtAuthClient.configure`
   block; the app defines `#jwt_payload`/`#jwt_secret` and has no initializer.
3. **Devise cannot authenticate anyone.** The `users` table has no `encrypted_password` or
   reset-password columns although `:database_authenticatable, :recoverable` are enabled.
4. **The root route points at a controller that does not exist**, CSP is disabled, HSTS/security
   headers are not set (the `header_guard` gem is in the Gemfile but unused), credentials have
   hardcoded development fallbacks, and the JWT is handed to clients in a URL query string.
5. **There is effectively no test suite** (one `pending` spec; the Minitest files cannot run: no
   `test_helper.rb`, test railtie disabled), no CI, and the bundle is not installable locally.
6. Three of the five self-developed gems are **out of date in the lock file** (`jwt_auth_client`
   0.1.0→0.2.0, `rack-jwt-verifier` 0.1.0→0.3.0, `header_guard` 0.1.1→0.3.1), and three of them
   (`header_guard`, `omniauth_syncer`, `rack-jwt-verifier`) are declared but never referenced.
   The lock is also out of sync with the Gemfile (`omniauth-oauth2` is declared in `Gemfile:26` but
   absent from the lock's `DEPENDENCIES`), so the Dockerfile's `BUNDLE_DEPLOYMENT=1` install refuses
   to run until the lock is regenerated.

The good news: the gems themselves are in far better shape than the app. `rack-jwt-verifier` 0.3.0 and
`header_guard` 0.3.1 are hardened, well-documented middlewares; `jwt_auth_client` 0.2.0 fails loudly
on misconfiguration. The recommended path is to **turn the app into a real OAuth 2.1 / OIDC
authorization server** whose token endpoint, userinfo endpoint and JWKS are consumed by the existing
client-side gems, and to expose the same capabilities to agents through an **MCP endpoint that uses
the hub itself as its OAuth authorization server**. Sections 6–7 detail this; `TODO.md` sequences it.

---

## 2. Method and constraints

- Read every file under `app/`, `config/` (excluding `master.key` and `credentials.yml.enc`), `db/`,
  `spec/`, `test/`, plus `Gemfile*`, `Dockerfile`, `docker-compose.yml`, `README.md`, `TODO.md`, `a`.
- Read the source and README of each self-developed gem from its sibling repository
  (`../jwt_auth_client`, `../rack_jwt_verifier`, `../omniauth-ssoprovider`, `../omniauth_syncer`,
  `../headerguard`) and compared the local version with `Gemfile.lock` and rubygems.org.
- `bundle show <gem>` fails in this environment (`Could not find puma-6.6.1, bigdecimal-3.3.1, …`):
  the bundle is not installed, so nothing below was verified by *running* the app. Findings are from
  reading code. Decisions taken with the user before the audit are recorded in the task file.

---

## 3. Self-developed gem inventory

| Gem | Locked | Local repo / rubygems | Used by the app? | Role |
|---|---|---|---|---|
| `jwt_auth_client` | 0.1.0 | **0.2.0** | yes — `app/models/user.rb:13` | Issues HS256 JWTs; `Issuable` mixin; Faraday client for service-to-service calls |
| `rack-jwt-verifier` | 0.1.0 | **0.3.0** | **no** | Rack middleware verifying JWTs (JWKS / PEM / HMAC), scopes, replay guard |
| `omniauth-ssoprovider` | 0.1.2 | 0.1.2 | yes — `config/initializers/omniauth_ssoprovider.rb:9` | OmniAuth OAuth2 *client* strategy (authorize → token → userinfo) |
| `omniauth_syncer` | 0.1.0 | 0.1.0 | **no** | Syncs an OmniAuth auth hash into a local AR model (client side) |
| `header_guard` | 0.1.1 | **0.3.1** | **no** | Rack middleware for HSTS, CSP, X-Frame-Options, COOP/CORP, Permissions-Policy |

All five are published on rubygems.org at the same version as the local repos; only the lock file is stale.

### 3.1 `jwt_auth_client` (0.2.0)

- **Provides**: `TokenIssuer.call(user_id:, target_service:, scopes:, claims:, expiry_seconds:)` →
  HS256/384/512 JWT with `iss sub aud scopes iat nbf exp jti`; `Issuable#to_jwt` driven by
  `#jwt_claims`; `HttpClient` (Faraday) minting a token per request; boot-time `configure` validation
  (shared key ≥ 32 bytes, `issuer` required, `none` rejected). Asymmetric signing "planned for 0.3.0".
- **How the app uses it**: `include JwtAuthClient::Issuable` (`app/models/user.rb:13`); `current_user.to_jwt`
  (`app/controllers/omniauth_callbacks_controller.rb:27`).
- **Gaps**:
  - `Issuable` does not exist in the locked 0.1.0 → `NameError` on `User` load.
  - `user.rb:32-46` defines `jwt_payload` and `jwt_secret`; 0.2.0's contract is `jwt_claims`
    (`issuable.rb:22-24`) and the signing key comes from `JwtAuthClient.configuration`, not the model.
    `to_jwt` raises `NotImplementedError`.
  - No `config/initializers/jwt_auth_client.rb`; 0.2.0 raises `ConfigurationError` without a
    shared key and `issuer`.
  - The model hardcodes `exp` (1 h) and `iss` in the claims (`user.rb:37-38`); 0.2.0 ignores/overrides
    registered claims, so these lines are dead.
  - **For a hub, HMAC is the wrong tool**: every client holding the shared key can mint tokens for
    every audience (the gem's own README says so). A hub must sign with a private key and publish a
    JWKS. → `[gem: jwt_auth_client]` implement the planned RS256/ES256 signing with `kid` (0.3.0), or
    let the hub sign with ruby-jwt directly and keep `jwt_auth_client` for service-to-service calls.

### 3.2 `rack-jwt-verifier` (0.3.0)

- **Provides**: everything a *resource server* needs — JWKS/PEM/HMAC key sources, key rotation with
  rate-limited refetch, `iss`/`aud` mandatory, `exp` required, leeway, `require_scopes` (RFC 6750
  `insufficient_scope`), `replay_cache` on `jti`, `skip` paths, JSON errors, `on_error` hook, Rack 2/3.
- **How the app uses it**: not at all (`grep RackJwtVerifier app config lib` → nothing).
- **Gaps / fit**: this is exactly the middleware the hub's own **API and MCP endpoints** should sit
  behind, verifying tokens the hub issued (JWKS from `/.well-known/jwks.json`, `aud: "mcp"` /
  `"hub-api"`). No change needed in the gem for that. `[app]` mount it; `[gem: rack-jwt-verifier]`
  optional: a helper that turns `env["rack_jwt_verifier.payload"]` into a `current_*` for controllers.

### 3.3 `omniauth-ssoprovider` (0.1.2)

- **Provides**: an `OmniAuth::Strategies::OAuth2` subclass (86 lines) that hits
  `client_options.site + /oauth/authorize`, `/oauth/token`, then `GET user_info_url` and exposes
  `uid = raw_info['id']`, `info.name/email`, `extra.raw_info`, `extra.access_token`.
- **How the app uses it**: mounted in `config/initializers/omniauth_ssoprovider.rb:6-31` with
  `SSO_HUB_URL` defaulting to `http://localhost:3000` — i.e. *this app pointing at itself*.
- **Gaps**: the gem is correct *for a client application*. In the hub it is architecturally wrong:
  the hub does not consume another SSO. Its value to this project is as the **contract** the hub must
  honour — `/oauth/authorize`, `/oauth/token`, `/api/v1/userinfo` returning `{id, name, email}` — and
  as the client half of the integration test. `[app]` remove the initializer from the hub; keep the
  gem as a dev/test dependency for an end-to-end "example client" spec. `[gem: omniauth-ssoprovider]`
  later: PKCE (`omniauth-oauth2 ≥ 1.8` supports `pkce: true`), `id_token` support, a documented
  `return_to`/`state` story, and a spec suite (there is none today).

### 3.4 `omniauth_syncer` (0.1.0)

- **Provides**: `SyncService.call(auth_hash)` → `find_or_initialize_by(uid_field)` + mapped attribute
  update + `save!`; `ControllerHelpers#sync_sso_user`.
- **How the app uses it**: not at all.
- **Gaps / fit**: client-side concern. The hub *owns* users, it does not sync them from elsewhere.
  `[app]` drop it from the hub's Gemfile (or keep in the example client only).
  `[gem: omniauth_syncer]` the gem itself: `engine.rb` is declared but not required from
  `lib/omniauth_syncer.rb`; `get_auth_value` has no tests; no spec suite in the repo.

### 3.5 `header_guard` (0.3.1)

- **Provides**: HSTS, `X-Content-Type-Options`, `X-Frame-Options`, `Referrer-Policy`, COOP, CORP,
  `X-Permitted-Cross-Domain-Policies`, `Permissions-Policy`, a strict default CSP (HTML only),
  `report_only`, `path_overrides`, option validation at boot.
- **How the app uses it**: not at all; Rails' own CSP initializer is fully commented out
  (`config/initializers/content_security_policy.rb`).
- **Gaps / fit**: drop-in for the hub. Its README already documents the identity-provider case
  (`Cross-Origin-Opener-Policy: unsafe-none` when the hub is opened as a popup; keep the default for
  redirect flows). CSP must allow importmap/Turbo (`script-src 'self'` + nonces, which Rails'
  `csp_meta_tag` in the layout expects). `[app]` mount it in `config/application.rb`.
  `[gem: header_guard]` optional: CSP nonce integration with Rails' `content_security_policy_nonce`.

---

## 4. What exists today (map)

| Area | Exists | State |
|---|---|---|
| Routes (`config/routes.rb`) | `devise_for :users`; `GET /up`; `GET /auth/:provider` → `passthru`; `GET /auth/:provider/callback` → `sso_provider_callback`; `root "home#index"` | root target missing; `/auth/*` are *OmniAuth client* paths; no provider endpoints |
| Controllers | `ApplicationController` (empty); `OmniauthCallbacksController` | `passthru` renders 404 (`:45`); callback reads `auth_data.extra.return_to` (`:23`) which the strategy never sets, treats `auth_data.uid` as a `client_id` (`:32`), puts the JWT in a query string (`:32`), rescues `StandardError` (`:36`) |
| Models | `User` (Devise + `Issuable`) | see §3.1; `is_admin` column exists but is unused |
| Views | `layouts/application.html.erb` only | no pages at all; Devise default views not generated; `hello_controller.js` boilerplate |
| DB | one migration `devise_create_users` | no `encrypted_password`, `reset_password_token/sent_at`; trackable columns present but `:trackable` not enabled; no tables for OAuth clients, grants, tokens, sessions, audit |
| Initializers | devise (defaults), omniauth_ssoprovider (client strategy), CSP (off), permissions_policy (off), filter_parameter_logging (default, good) | no `rack-cors` config although the gem is present; no `jwt_auth_client`, `header_guard`, `rack_jwt_verifier` config |
| Deployment | `Dockerfile` (Rails 7.1 default, fine), `docker-compose.yml` | compose is dev-only: `RAILS_ENV: development`, hardcoded `development_password`, source bind-mount; no production compose / no `.env` wiring (`JWT_SERVICE_SECRET` commented) |
| Tests | `spec/models/user_spec.rb` (pending), empty factory; `test/models/user_test.rb`, `test/initializers/…` | Minitest files `require "test_helper"` which does not exist and `rails/test_unit/railtie` is commented out (`config/application.rb:15`); no CI |
| Docs | `README.md`, `TODO.md` (3 bytes), `a` (2.2 KB pasted chat) | README's second half is a pasted assistant transcript (Vue.js E2E crypto, Phase 1/2/3) that does not match the code |
| Runtime | Ruby 3.1.4, Rails 7.1.5.2, Postgres 14 (compose) | Ruby 3.1 and Rails 7.1 are past their upstream security-maintenance windows as of this audit date — verify and plan an upgrade |

---

## 5. Findings per area

### 5.1 Security

**Current state**
- Consumer strategy with hardcoded fallback client id / client key `development_id` /
  `development_secret` (`config/initializers/omniauth_ssoprovider.rb:10-11`) and default `SSO_HUB_URL`
  over `http://`.
- JWT returned to the client via `redirect_to "#{redirect_uri}?token=…"` (`omniauth_callbacks_controller.rb:32`):
  tokens land in browser history, proxy logs, `Referer` headers. `redirect_uri` is taken from the auth
  hash without validation → open redirect once the value is populated.
- HMAC-signed tokens (`jwt_auth_client`), key intended to come from Rails credentials
  (`user.rb:45`) but the 0.2.0 gem reads `JWT_SERVICE_SECRET`; whichever it is, one shared key
  for all clients.
- Devise: `:registerable` on (anyone can create a hub account), `password_length = 6..128`,
  no `:confirmable`, `:lockable`, `:timeoutable`, `:trackable`, no 2FA, placeholder `mailer_sender`.
- CSP off; no HSTS / frame / referrer headers (`header_guard` unused); `permissions_policy.rb` empty;
  `force_ssl = true` in production (good); `filter_parameters` covers `token`/`secret` (good).
- `rescue StandardError` in the callback swallows every error into a flash message (`:36-39`).
- No rate limiting, no audit log, no session/token revocation, no client registry (so no
  `redirect_uri` allow-list, no hashed client keys, no per-client scopes).
- `docker-compose.yml` ships `POSTGRES_PASSWORD: development_password` in the repo.

**Desired state**
- The hub is an OAuth 2.1 authorization server: authorization-code flow with PKCE (mandatory for
  public clients, allowed for all), exact-match `redirect_uri` allow-list per registered client,
  `state` handled by the client gem, tokens delivered only via the back-channel token endpoint
  (never in URLs), short-lived access tokens (5–15 min) + rotating refresh tokens, revocation
  (RFC 7009) and introspection (RFC 7662) endpoints, JWKS with `kid` and key rotation.
- Access/ID tokens signed asymmetrically (RS256 or ES256); private key from the environment or a KMS;
  clients verify with `rack-jwt-verifier` `jwks_url:`.
- Devise hardened: registration off (admin-created or invitation), `:confirmable :lockable
  :timeoutable :trackable`, password length ≥ 12 (+ pwned-password check), optional TOTP 2FA for
  admins first.
- `header_guard` mounted with a CSP that permits importmap + Turbo via nonces; COOP per README's IdP
  guidance; `rack-cors` configured only for the token/userinfo/MCP endpoints.
- Per-client and per-IP rate limiting on `/oauth/token`, sign-in and password reset; structured
  audit log of sign-ins, grants, token issuance/revocation, admin actions.
- Errors handled explicitly (OAuth error responses per RFC 6749 §4.1.2.1 / §5.2), not blanket rescues.

**Gap** — everything above is missing; the items marked *wrong* in §8 must be removed before any of it
is added, because they encode the wrong architecture.

### 5.2 Performance

**Current state** — nothing to measure yet: one table, no endpoints. Puma config is the Rails default
(threads 5, workers = CPU count in production), bootsnap enabled, `Rails.cache` unconfigured (defaults
to file store in production — wrong for multi-worker replay/rate-limit state).

**Desired state**
- Token endpoint p95 < 50 ms: indexed lookups on `client_id`, `code`, `refresh_token` digests; no
  N+1; signing key loaded once per process (not per request).
- JWKS served with `Cache-Control: public, max-age=300` and ETag so clients (and
  `rack-jwt-verifier`'s cache) hit the hub once per TTL.
- `Rails.cache` on Redis (or Postgres via Solid Cache) shared across workers for: `jti` replay
  guard, rate-limit counters, authorization-code single-use.
- Health check split: `/up` (liveness) and a readiness check that verifies DB + cache + signing key.
- Request logging in JSON with `request_id`, `client_id`, `sub` (already `log_tags = [:request_id]`).

**Gap** — infra choices (Redis vs Solid Cache) are open; the rest is straightforward once endpoints
exist. Deployment target is Docker/single host (decided), so a production `docker-compose.prod.yml`
with `web`, `db`, `cache` and a reverse proxy terminating TLS is the reference deployment.

### 5.3 Ease of use / UX-UI

**Current state** — no UI at all. `root "home#index"` → `ActionController::RoutingError`
(no `HomeController`, no `app/views/home/`). Devise views are the gem defaults (not generated, not
styled). `hello_controller.js` is scaffolding.

**Desired state** (simple but complete, server-rendered with Turbo/Stimulus — already in the bundle;
no SPA):
- Public: sign-in, sign-out, password reset, (optional) email confirmation, consent screen for the
  authorization request ("*Client X* wants to access your *profile, email*").
- User: account page (name, email, password change, 2FA enrolment), "connected apps" with per-grant
  revoke, active sessions with "sign out everywhere".
- Admin (`is_admin`): client applications CRUD (name, redirect URIs, client type public/confidential,
  scopes, client-key rotation with one-time display), users list/search/disable/promote, tokens &
  grants view with revoke, audit log viewer, signing-key rotation status.
- Developer: a "how to integrate" page that prints the exact `omniauth-ssoprovider` initializer for a
  given client (site, endpoints, scopes) and the `rack-jwt-verifier` snippet — the hub's own gems as
  the documented SDK.
- Consistent minimal styling (one stylesheet, no framework, or Pico/Simple.css-class minimal CSS),
  keyboard/screen-reader friendly forms, flash messages, error pages.

**Gap** — all of it. The list above is also the **capability list the MCP endpoint must mirror** (§6).

### 5.4 Functionality (incl. MCP endpoint)

**Current state** — provider functionality: none. What the code attempts (`OmniauthCallbacksController`)
is the *client* leg of an OAuth2 flow against a hub that does not exist, followed by a redirect with a
JWT in the query string — a bespoke, non-standard "flow" that no client gem (including the user's own)
speaks. MCP: nothing.

**Desired state** — the hub speaks, at minimum, what `omniauth-ssoprovider` expects, and converges on
standard OAuth 2.1 / OIDC so any off-the-shelf client also works:

| Endpoint | Purpose | Consumer |
|---|---|---|
| `GET /oauth/authorize` | auth-code + PKCE, consent, `redirect_uri` allow-list | `omniauth-ssoprovider`, MCP clients |
| `POST /oauth/token` | code → access (JWT, RS256, `kid`) + refresh + `id_token`; refresh rotation; client auth (client key or PKCE-only public) | same |
| `GET /api/v1/userinfo` | `{id, sub, name, email, roles}` from bearer token | `omniauth-ssoprovider` (its `raw_info['id']` → `uid`) |
| `GET /.well-known/openid-configuration`, `/.well-known/oauth-authorization-server` | discovery (RFC 8414) | MCP clients, generic OIDC clients |
| `GET /.well-known/jwks.json` | public keys with `kid` | `rack-jwt-verifier` in every client/resource server |
| `POST /oauth/revoke`, `POST /oauth/introspect` | RFC 7009 / 7662 | clients, MCP server, admin UI |
| `POST /oauth/register` | dynamic client registration (RFC 7591), gated/approval-based | MCP clients (agents) |
| `POST /mcp` (+ SSE) | MCP Streamable HTTP endpoint, bearer-protected | agents |
| `GET /.well-known/oauth-protected-resource` | RFC 9728 metadata pointing at the hub's AS | MCP clients |

**Build vs. buy for the authorization server** — decision for the user, recommendation first:
- **(A) Doorkeeper + doorkeeper-openid_connect** `[app]` + new dependency — mature, audited
  implementation of every endpoint above except MCP; PKCE, refresh rotation, revocation, introspection,
  JWKS come for free; the app supplies the consent UI, client admin UI and the `userinfo`/claims
  mapping. Fastest path to "production-ready" for the security-critical core.
- **(B) Own implementation extracted as `[new gem]` `sso_hub` (or similar)** — consistent with the
  "own gems" strategy, but an authorization server is the last thing to hand-roll: code/redirect/PKCE
  validation, client auth, token rotation and revocation have many subtle failure modes. If chosen,
  build it *behind the same interface* as (A) and port Doorkeeper's spec cases.
Either way the user's gems stay first-class: `omniauth-ssoprovider` is the reference client,
`rack-jwt-verifier` protects the hub's own API/MCP and every downstream service, `header_guard`
hardens responses, `jwt_auth_client` handles hub → service calls (e.g. webhooks, syncing to a
"licenses/tenancy" service — the topic of the stray file `a`).

**Gap** — total. Sequencing is in `TODO.md`: fix the foundations (schema, gems, rules), remove the
wrong client-side wiring, add the AS, then UI, then MCP.

### 5.5 Tests

**Current state**
- RSpec: `spec/models/user_spec.rb` is `pending`; `spec/factories/users.rb` defines an empty
  factory; `rails_helper.rb` is the generator default. `harness.yaml` runs `bundle exec rspec`.
- Minitest: `test/models/user_test.rb` (3 tests, would fail: no `encrypted_password`, no
  `jwt_claims`, reads `credentials.sso_hub_client_secret`), `test/initializers/omniauth_ssoprovider_test.rb`
  (asserts the *client* strategy is mounted). Both `require "test_helper"`, which does not exist, and
  `rails/test_unit/railtie` is disabled → the suite cannot run at all.
- No CI, no coverage, no lint (`rubocop` absent), no security scanners (`brakeman`,
  `bundler-audit`), no system/browser tests.
- The bundle does not install in this environment (stale lock, missing platform gems).

**Desired state** (RSpec canonical — decided)
- Model specs (User validations, sso_id, admin flag), request specs for every OAuth endpoint
  including negative cases (bad `redirect_uri`, missing PKCE verifier, replayed code, expired refresh
  token, revoked token, wrong `aud`), discovery/JWKS specs, userinfo spec, MCP request specs
  (initialize, tools/list, each tool, unauthenticated → 401 with `WWW-Authenticate` + resource
  metadata), system specs for sign-in → consent → redirect, an **end-to-end spec that mounts
  `omniauth-ssoprovider` as a client inside the test** and completes a real login against the hub,
  and a spec that `rack-jwt-verifier` (JWKS mode) accepts the hub's tokens.
- `test/` removed; `rails/test_unit/railtie` stays off.
- CI (GitHub Actions): `bundle install`, `db:prepare`, `rspec`, `rubocop`, `brakeman`,
  `bundler-audit`, Docker build.

**Gap** — all of it; the interop specs in `rack_jwt_verifier`'s own repo are a good template.

---

## 6. MCP endpoint and agent authentication

**Principle (decided):** anything a user can do in the UI, an agent can do via MCP. The MCP server is
a first-class interface of the hub, implemented inside the app and authorized by the hub itself.

### 6.1 Capabilities to mirror (from §5.3)

| UI capability | MCP tool (proposed name) | Required scope |
|---|---|---|
| Who am I / my profile | `whoami`, `get_profile`, `update_profile` | `profile` |
| My connected apps, revoke a grant | `list_grants`, `revoke_grant` | `profile` |
| My sessions, sign out everywhere | `list_sessions`, `revoke_sessions` | `profile` |
| Admin: clients CRUD, rotate client key | `list_clients`, `create_client`, `update_client`, `rotate_client_secret`, `delete_client` | `admin:clients` |
| Admin: users list/disable/promote | `list_users`, `get_user`, `disable_user`, `set_admin` | `admin:users` |
| Admin: tokens/grants, revoke | `list_tokens`, `revoke_token` | `admin:tokens` |
| Admin: audit log | `search_audit_log` | `admin:audit` |
| Developer: integration snippet | `integration_snippet(client_id, framework)` | `profile` |
| Verify a token (for other agents/services) | `introspect_token` | `introspect` |
| Read-only reference | MCP *resources*: `hub://openid-configuration`, `hub://jwks`, `hub://clients/{id}` | as above |

Every tool call is executed through the **same service objects the controllers use** (`[app]`
`app/services/...`), so authorization, validation and audit logging are shared, not duplicated.
Password changes and 2FA enrolment are deliberately *not* exposed via MCP.

### 6.2 Agents logging in through the hub

The MCP authorization specification is built on OAuth 2.1: the MCP server is an OAuth **resource
server**; it advertises its **authorization server** through Protected Resource Metadata
(`/.well-known/oauth-protected-resource`, RFC 9728) returned alongside a `401` +
`WWW-Authenticate: Bearer resource_metadata="…"`; clients discover the AS via RFC 8414 metadata,
register dynamically (RFC 7591) if allowed, run authorization-code + PKCE, and must send a `resource`
indicator (RFC 8707) so the token is bound to this MCP server. **The hub can be that authorization
server**: an agent's login *is* an SSO login. Concretely:

1. Agent (MCP client) calls `POST /mcp` without a token → `401` with resource metadata naming
   `https://hub/` as the AS.
2. Agent reads `/.well-known/oauth-authorization-server`, registers via `/oauth/register` (or uses a
   pre-registered `client_id`), and opens `/oauth/authorize?…&code_challenge=…&resource=https://hub/mcp&scope=profile admin:clients`.
3. The human signs in with Devise (+2FA), sees a consent screen listing the agent and scopes, approves.
4. Agent exchanges the code at `/oauth/token`, gets a JWT with `aud: "https://hub/mcp"`, `sub: <sso_id>`,
   `scopes: [...]`, `azp: <agent client_id>`, short `exp`, plus a refresh token.
5. `rack-jwt-verifier` (JWKS from the hub itself, `aud` = the MCP resource, `require_scopes` per
   tool) guards `/mcp`; tool handlers read `sub`/`scopes` from `env["rack_jwt_verifier.payload"]`.

Machine-only agents (no human) use the **client-credentials grant** with a confidential client
created by an admin, restricted scopes and `sub = client_id` — audited like any other principal.

### 6.3 Required changes to the token model

| Change | Why | Placement |
|---|---|---|
| Asymmetric signing (RS256/ES256) with `kid`, published JWKS, rotation | resource servers must not be able to mint tokens; MCP clients expect JWKS | `[gem: jwt_auth_client]` 0.3.0 (planned there) or `[app]` via ruby-jwt |
| `aud` = resource indicator (`https://hub/mcp`, `https://hub/api`, client ids) | RFC 8707; `rack-jwt-verifier` already enforces `aud` | `[app]` |
| `scopes` claim as array (what `rack-jwt-verifier` reads) + `scope` string for OAuth clients | interop both ways | `[app]` / `[gem: rack-jwt-verifier]` already supports both |
| `azp` / `client_id` claim | know which agent acted on behalf of `sub` for audit | `[app]` |
| Refresh tokens (opaque, hashed at rest, rotated, family-revocation on reuse) | agents run long; access tokens stay short | `[app]` (Doorkeeper provides) |
| Persisted token/grant records + revocation + introspection | "sign out everywhere", admin revoke, MCP `introspect_token` | `[app]` |
| Client registry with `client_type` (public/confidential), `redirect_uris`, allowed scopes, `dynamic: true` flag and approval state | RFC 7591 for agents without open registration abuse | `[app]` |
| Consent records per (user, client, scopes) | skip consent on repeat, list "connected apps" | `[app]` |
| `jti` replay guard on `/mcp` and `/api` via shared cache | `rack-jwt-verifier` `replay_cache:` | `[app]` infra |

Implementation note: the MCP transport/protocol layer (JSON-RPC, `initialize`, `tools/list`,
Streamable HTTP/SSE) should come from the official Ruby `mcp` gem `[app]` + new dependency, with a
thin Rails controller. The *authorization glue* — "protect an MCP endpoint with an OAuth AS and
`rack-jwt-verifier`, emit RFC 9728 metadata and the `WWW-Authenticate` challenge" — is generic and a
good candidate for a `[new gem]` (e.g. `rack-mcp-auth`) or a feature of `[gem: rack-jwt-verifier]`
(an `on_error` preset that adds `resource_metadata` to the challenge).

---

## 7. Explicitly required findings (each with a recommendation)

| # | Finding | Evidence | Recommendation |
|---|---|---|---|
| E1 | Root route → non-existent `HomeController` | `config/routes.rb:26`; no `app/controllers/home_controller.rb` | Add `HomeController#index` as the landing page (signed-out: sign-in CTA; signed-in: dashboard/account). `[app]` |
| E2 | CSP disabled | `config/initializers/content_security_policy.rb` all comments | Delete the Rails initializer and mount `header_guard` with a nonce-aware CSP; keep `csp_meta_tag`. `[app]` |
| E3 | Duplicate `spec/` and `test/` | both dirs; `test_helper.rb` missing; test railtie off | Delete `test/`; port the three Minitest cases to RSpec model specs. `[app]` |
| E4 | Stray file `a` | 2.2 KB pasted chat about licences/multi-tenancy | Delete; fold its one useful idea ("licensing/tenancy is a separate service that trusts the hub's tokens") into `docs/ARCHITECTURE.md`. `[app]` |
| E5 | OmniAuth consumer vs. provider ambiguity | `config/initializers/omniauth_ssoprovider.rb`, `OmniauthCallbacksController`, routes `/auth/:provider*`, `test/initializers/…` | The hub is the **provider**. Remove the client strategy, the `/auth/*` routes and the callback controller from the hub; implement provider endpoints (§5.4); keep `omniauth-ssoprovider` as a test/dev dependency for the E2E client spec and as the documented client SDK. `[app]` |

---

## 8. Rollups per area

### Security
- **Wrong**: JWT in redirect query string; unvalidated `redirect_uri`; hardcoded fallback client id/key; HMAC shared key as the hub's signing key; blanket `rescue StandardError`; `:registerable` open; dev DB password in compose.
- **Needs improvement**: Devise password policy; Devise modules; `filter_parameters` fine; `force_ssl` fine.
- **Missing**: OAuth 2.1 AS (PKCE, allow-lists, rotation, revocation, introspection); asymmetric keys + JWKS; `header_guard`; `rack-cors` config; rate limiting; audit log; 2FA; brakeman/bundler-audit in CI; configuration via env/KMS with no fallbacks.
- **Should be removed**: client strategy initializer; `/auth/*` routes; `OmniauthCallbacksController`; `sso_hub_client_secret` credential usage in the model.

### Performance
- **Wrong**: `Rails.cache` unconfigured while replay/rate-limit state will need to be shared.
- **Needs improvement**: Puma defaults acceptable; add `WEB_CONCURRENCY`/`RAILS_MAX_THREADS` to the prod compose.
- **Missing**: shared cache (Redis/Solid Cache); JWKS caching headers; readiness check; JSON logs; indices on token/code tables; production compose with reverse proxy.
- **Should be removed**: nothing.

### Ease of use / UX-UI
- **Wrong**: root route broken; `passthru` renders 404.
- **Needs improvement**: layout is bare; Devise views not generated.
- **Missing**: every page listed in §5.3; consent screen; admin; developer integration page; flash/error pages; minimal CSS.
- **Should be removed**: `hello_controller.js`.

### Functionality
- **Wrong**: app acts as OAuth client of itself; `to_jwt` contract mismatch; Devise schema mismatch; lock file pins gem versions incompatible with the code.
- **Needs improvement**: `User` (add `disabled_at`, roles beyond `is_admin` if needed).
- **Missing**: all provider endpoints; discovery; client registry; grants/tokens/sessions; MCP endpoint and tools; dynamic registration; client-credentials grant; email delivery config.
- **Should be removed**: `omniauth_syncer` from the hub Gemfile; README's pasted transcript; `TODO.md` stub.

### Tests
- **Wrong**: Minitest files that cannot load; tests asserting the client strategy is mounted.
- **Needs improvement**: `rails_helper` (add FactoryBot syntax, Devise/Warden helpers, WebMock).
- **Missing**: everything in §5.5; CI; rubocop; coverage.
- **Should be removed**: `test/`.

---

## 9. Gem-level follow-ups (for the user's other repos)

| Gem | Item | Priority |
|---|---|---|
| `jwt_auth_client` | 0.3.0: RS256/ES256 signing with `kid`; optional JWKS publisher helper | high (hub needs asymmetric keys) |
| `rack-jwt-verifier` | optional RFC 9728 `resource_metadata` in the `WWW-Authenticate` challenge (MCP); controller helper for `current_token` | medium |
| `omniauth-ssoprovider` | `pkce: true` default; `id_token` handling; spec suite; document `state`/return-to; expose `roles` in `info` | medium |
| `omniauth_syncer` | require `engine` properly or drop it; spec suite | low |
| `header_guard` | Rails CSP nonce integration helper | low |

## 10. Open questions (do not block TODO.md)

1. Authorization-server core: Doorkeeper (recommended) or own gem? (§5.4)
2. Shared cache backend: Redis or Solid Cache (Postgres)?
3. Email delivery provider for confirmation/reset (needed before `:confirmable`).
4. Should `/oauth/register` be open (with rate limits) or approval-gated for agents?
5. Ruby/Rails upgrade timing (3.1/7.1 are past upstream maintenance).
