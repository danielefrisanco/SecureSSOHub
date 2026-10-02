# SecureSSOHub — architecture

Living document. The current-state audit that motivated it is [`AUDIT.md`](AUDIT.md); the backlog is
[`../TODO.md`](../TODO.md). Update the decisions log whenever a phase gate or task settles something.

## 1. Purpose

SecureSSOHub is the single place where people (and agents acting for them) authenticate. It owns
user accounts, performs login, and issues short-lived signed tokens that every other application and
service in the ecosystem trusts. It does **not** own business authorization data.

## 2. Roles

| Component | Role |
|---|---|
| **SecureSSOHub** (this app) | OAuth 2.1 / OpenID Connect **authorization server** and identity provider: user accounts, sign-in, consent, client registry, token issuance, revocation, introspection, discovery, JWKS. Also a **resource server** for its own API and the MCP endpoint. |
| Client applications | OAuth clients (confidential or public + PKCE). Consume the hub's tokens with `omniauth-ssoprovider` (login) and verify them with `rack-jwt-verifier` (JWKS). |
| Downstream services / APIs | Resource servers verifying hub tokens with `rack-jwt-verifier`; may call each other with `jwt_auth_client`. |
| Agents (MCP clients) | OAuth clients that obtain tokens through the hub (authorization-code + PKCE, or client credentials for machine agents) and call the hub's MCP endpoint. |

## 3. Trust boundaries

- The hub's **private signing key** never leaves the hub; everyone else verifies with the published
  JWKS. Shared-secret (HMAC) signing is a stopgap only.
- **Access tokens** are RS256 JWTs (RFC 9068: header `typ: at+jwt`, `kid` of the signing key) built by
  `OAuth::TokenPayload`. Resource servers must check `iss` and `aud` — `rack-jwt-verifier` refuses to
  boot without them.

  | claim | value |
  |---|---|
  | `iss` | `HUB_ISSUER` |
  | `sub` | the user's `sso_id`; the client's `client_id` for client-credentials tokens |
  | `aud` | the RFC 8707 `resource` of the authorization request, else the client's `client_id` |
  | `azp` | the client the token was issued to (audit, MCP) |
  | `scope` / `scopes` | space-delimited string (OAuth) and array (what `rack-jwt-verifier` reads) |
  | `jti` | unique per token (UUID) |
  | `iat`, `nbf`, `exp` | issued-at, not-before (= `iat`), expiry = `iat` + 10 minutes |
  | `name` | only with the `profile` scope |
  | `email`, `email_verified` | only with the `email` scope |
  | `admin` | boolean, `true` only for administrators (user tokens only) |

  Nothing else about the user is placed in an access token, and a machine token (client-credentials,
  no user) carries no user claim at all — not even `admin`. The same scope gating applies to the
  id_token (`openid` scope; `sub`, `iss`, `aud` = client_id, `nonce`, `auth_time`, `at_hash`) and to
  userinfo. Refresh tokens are opaque, hashed at rest, issued only with `offline_access`.
- **Revocation vs self-contained tokens.** Revoking a token (RFC 7009 endpoint, sign out everywhere,
  client or consent revocation) takes effect at once for the hub's own API and MCP endpoint (they check
  the `jti` against the token record), for introspection callers and for the refresh flow. A resource
  server that verifies the JWT offline cannot know: it keeps accepting a revoked access token until its
  `exp` — at most **10 minutes**. Resource servers must accept that window, or call
  `POST /oauth/introspect` (a confidential client registered with the `introspect` scope) before a
  sensitive operation; a refresh token is never a credential for a resource server and introspects as
  inactive.
- **Licensing, multi-tenancy and complex authorization live in a separate, connected service** that
  trusts the hub's tokens; the hub only asserts *who* (and which client) — never entitlements.
  Roles/claims the hub does expose are minimal (`admin`) and are inputs to that service, not a
  replacement for it.
- Tokens are never placed in URLs; they travel through the back-channel token endpoint or the
  `Authorization` header.

## 4. Authorization-server core and the own gems

**Decision (2026-09-18):** the OAuth 2.1 / OIDC core is [Doorkeeper](https://github.com/doorkeeper-gem/doorkeeper)
plus `doorkeeper-openid_connect`. Building an own authorization-server gem stays an open option.

**Isolation rule that makes the swap possible:** Doorkeeper is wrapped by the app's own service
layer (`app/services/…`, TODO T37). Controllers, views, MCP tools and jobs call those services —
never `Doorkeeper::Application`, `Doorkeeper::AccessToken` or Doorkeeper helpers directly — and the
services expose hub-level concepts (client, grant, token, consent). Specs for the OAuth endpoints are
written against the HTTP contract, not against Doorkeeper internals, so they survive a replacement.

**Client registry (TASK-016):** clients are `Doorkeeper::Application` rows extended with the hub's
columns (`client_type`, `approval_state`, `registered_via`, `owner_id`, RFC 7591 metadata,
`last_used_at`). The rules live in `OAuth::ClientRules` (included from the Doorkeeper initializer, so
`app/models` never names Doorkeeper): `client_type` is the source of truth and public clients have no
secret; redirect URIs must be absolute https, http only on loopback hosts, private-use schemes only
for public clients, no fragments/userinfo/OOB; scopes come from `config/oauth_scopes.yml`; approval
moves pending → approved, pending → revoked, approved → revoked (final). `OAuth::Clients` is the
only API (admin-only mutation with one-time secrets; `register_dynamic` is the single no-actor path,
for RFC 7591, and never grants `admin`/`machine` scopes). Rotating a secret leaves issued tokens valid.

**Authorization endpoint (TASK-017):** `GET/POST /oauth/authorize` is Doorkeeper's controller with the
hub's rules prepended from the initializer: `OAuth::AuthorizationRules` (into the pre-authorization
check) requires S256 PKCE from public clients, allows it for confidential ones and never accepts
`plain`; matches `redirect_uri` exactly (only a loopback port may differ, RFC 8252); validates the
optional RFC 8707 `resource` against `OAuth::Resources.known` (`#{HUB_ISSUER}/api`, `#{HUB_ISSUER}/mcp`)
with `invalid_target` and stores it on the grant and token (the token's `aud`; absent → the client's own
client_id). `OAuth::AuthorizationGuard` (into the controller) signs out a disabled user and answers
`access_denied`. Only approved clients pass (`unauthorized_client`). Errors are redirected to the client
once client and `redirect_uri` are verified, rendered before that — never a redirect to an unverified URI.

**Consent (TASK-018):** `config/oauth_scopes.yml`, wrapped by `OAuth::Scopes`, is the single scope
catalogue (description, `default`/`admin`/`machine` flags); a spec fails if a scope lacks a description.
A user's standing consent per client is an `oauth_consents` row (one live row per user and client,
scopes merged on every grant, `revoked_at` closes it and `OAuth::Tokens.revoke_for` drops that client's
tokens for the user) behind `OAuth::Consents` (`covers?`/`granted_scopes`/`grant`/`revoke`/`for`).
Doorkeeper's `skip_authorization` asks `covers?`, so a repeat request for a subset of the consented
scopes gets its code without a page; a superset or a revoked consent asks again. The page itself is
`app/views/doorkeeper/authorizations/new.html.erb` driven by `OAuth::ConsentScreen` (prepended into the
authorizations controller): application layout under the CSP (this controller alone widens `img-src`
to https for the client logo and `form-action` to the validated redirect target, which browsers check
against the redirect that follows Allow/Deny), scope descriptions with new scopes highlighted, and
Allow/Deny forms that carry `resource` and `nonce` as well as Doorkeeper's fields. Only administrators
may consent to `admin:*` scopes (`invalid_scope` otherwise, in `OAuth::AuthorizationRules`).

**Token endpoint (TASK-019):** `POST /oauth/token` is Doorkeeper's controller with `OAuth::TokenRules`
prepended into the authorization-code and refresh-token requests. Client authentication is Doorkeeper's:
confidential clients send their secret with `client_secret_basic` or `client_secret_post`, public clients
send none (a public client presenting a secret, or a confidential one without, is `invalid_client`); the
code must match the client, the `redirect_uri` and the S256 `code_verifier` (`invalid_grant`), and expires
after one minute. Every token remembers the code it descends from (`oauth_access_tokens.access_grant_id`,
kept across refresh rotations): a replayed code answers `invalid_grant` and revokes every token issued from
it. Refresh tokens are issued only with `offline_access`, rotate on every use — Doorkeeper revokes the used
one immediately under a row lock because the schema deliberately has no `previous_refresh_token` column —
and presenting an already-rotated token (`OAuth::Tokens.detect_reuse!`) revokes every live token and code
the client holds for that user. Their lifetime is absolute (`OAUTH_REFRESH_TOKEN_TTL`, 30 days from the
code). The id_token gets the hub's `at_hash` over the JWT the client received (`OAuth::IdToken`), and
`oauth_applications.last_used_at` is touched on every successful response.

**Userinfo and the API guard (TASK-020):** two userinfo endpoints serve the same token. `GET /oauth/userinfo`
is doorkeeper-openid_connect's (OIDC claims, `sub` + the scope-gated `name`/`email`/`email_verified`;
Doorkeeper finds the token by the hash of the presented JWT). `GET /api/v1/userinfo` is the document
`omniauth-ssoprovider` hard-codes — `{id, sub, name, email, email_verified, roles}`, `id`/`sub` = `sso_id`,
`roles` = `["admin"]` or `[]`, `name`/`email` gated by `profile`/`email` — and the first endpoint of the hub's
bearer-token API. `/api/**` sits behind `rack-jwt-verifier` (`config/initializers/rack_jwt_verifier.rb`):
RS256 only, `iss` = `HUB_ISSUER`, `aud` = `OAuth::Resources.hub_api` (a token minted for the client itself or
for the MCP endpoint is `invalid_token`), 30 s leeway, token required, JSON errors with the RFC 6750
challenge, everything outside `/api` skipped. Key material never leaves the process: the hub's JWKS (active
and previous key) is handed to ruby-jwt as the `jwks` decode option, resolved per request from
`OAuth::SigningKey` (gem follow-up T48). What a self-contained JWT cannot say is checked per request in
`Api::BaseController`: the token's `jti` — chosen on the record before the JWT is generated
(`OAuth::TokenRecord`, indexed `oauth_access_tokens.jti`) — must still be live (`OAuth::Tokens.active?`),
and the user must not be disabled; both answer 401 `invalid_token`. The gem's `replay_cache` stays off
(TASK-027): it refuses a second use of any `jti`, and a bearer access token is presented on every call for its
lifetime (RFC 6750) — a spec proves a token is accepted repeatedly. It fits one-time tokens (DPoP proofs, T61).
The interop spec (`spec/integration/rack_jwt_verifier_flow_spec.rb`) runs the gem as shipped, in
JWKS mode against the hub's own document, as the proof downstream services need nothing hub-specific.

**Revocation, introspection, sign out everywhere (TASK-022):** `POST /oauth/revoke` (RFC 7009) and
`POST /oauth/introspect` (RFC 7662) are Doorkeeper's controller with `OAuth::RevocationRules` prepended.
Revocation keeps Doorkeeper's client authentication (secret for confidential clients, `client_id` alone for
public ones), 200 for an unknown token and 403 `unauthorized_client` for another client's token (RFC 7009
§2.1: refused and informed; the token stays active); `token_type_hint` only orders the lookup, and a
revoked token takes its family — every live token issued from the same code — with it
(`OAuth::Tokens.revoke_family!`). Introspection needs client authentication (`OAuth::IntrospectionRules`:
no bearer-token callers, 401 `invalid_client` otherwise); only a confidential, approved client registered with
the machine scope `introspect` learns anything (`OAuth::Introspection.allowed?`), everyone else gets
`{"active": false}`, as do revoked, expired, unknown and refresh tokens. An active access token is described
by `active`, `scope`, `client_id`, `username` (`sso_id`, absent for `client_credentials`), `token_type`,
`exp`, `iat` and the JWT's own `sub`, `aud`, `iss`, `jti`. `OAuth::Tokens` offers the same operations to the
rest of the app: `revoke(token_or_jti, by:)` (owner or admin), `revoke_all_for(user:)`, `revoke_for(user:,
client_uid:)`, `revoke_all(client_uid:)` and `active_for(user:)` (live sessions, refresh-backed ones
included). A password change or reset and an administrator setting `disabled_at` revoke every token and
pending code of the user (`User` callback); signing out of the hub and a failed-attempts lock do not.

**Machine grant (TASK-024):** `client_credentials` (RFC 6749 §4.4) gives a service with no user behind it
a token for itself. `OAuth::MachineGrantRules`, prepended into Doorkeeper's grant validator, admits only
confidential, approved clients (`unauthorized_client`; Doorkeeper answers it with 401 where RFC 6749 §5.2
would say 400) and only machine scopes: a client's machine allow-list is its registered scopes carrying
the `machine` flag in `config/oauth_scopes.yml` (no extra column); user and admin scopes are
`invalid_scope` even when registered, and a request without `scope` falls back to the default `openid`
and is refused too. An optional RFC 8707 `resource` is validated as at the authorization endpoint
(`invalid_target`) and becomes `aud`; otherwise `aud` is the client's `client_id`. The token is the §3
JWT with `sub` = `azp` = `client_id`, no user claims, 10 minutes, no refresh token. Doorkeeper creates it
inside `OAuth::Tokens.issue_client_token`, the one hook for machine-token issuance (audit log, T25), which
also touches `last_used_at`. A client's earlier token is neither reused nor revoked
(`revoke_previous_client_credentials_token` off), so a service can roll over. Introspection is unchanged:
a service holding `introspect` calls it with its own client credentials; its machine token is never a
caller credential there.

**Dynamic client registration (TASK-025):** `POST /oauth/register` (RFC 7591) is the hub's own
`ClientRegistrationsController`; `OAuth::DynamicRegistration` validates the JSON metadata and calls
`OAuth::Clients.register_dynamic`, the registry's only entry point without an administrator.
`OAUTH_REGISTRATION_POLICY` (`OAuth::RegistrationPolicy`, validated at boot): `approval` (default) creates
the client `pending` — refused at authorize and token until `OAuth::Clients.approve`; `open` approves at
once but only public (PKCE) clients; `closed` answers 404 and drops `registration_endpoint` from both
discovery documents. Registration never grants `admin:*` or machine scopes, nor `client_credentials`
(`grant_types` ⊆ authorization_code, refresh_token). Redirect-URI problems are `invalid_redirect_uri`,
everything else `invalid_client_metadata` (400, RFC 7591 §3.2.2) — including a duplicate (same
`client_name` and `redirect_uris` within 24 hours; RFC 7591 defines no 409). Until rate limiting (T24): at
most `OAUTH_REGISTRATION_IP_LIMIT` registrations per address and hour (`oauth_applications.registration_ip`,
429 `temporarily_unavailable` with `Retry-After`), and bodies over 16 KiB get 413 from `RequestBodyLimit`
before Rails parses them. The response is `no-store` (it may carry the one-time `client_secret`), and each
registration is logged with its `client_id` and address. No RFC 7592 management endpoint yet (T59).

**Role of each self-developed gem in the target architecture**

| Gem | Where | Role |
|---|---|---|
| `jwt_auth_client` | services calling each other (not the hub today) | service → service calls with `HttpClient`. Removed from the hub in TASK-019: access tokens are minted by doorkeeper-jwt + `OAuth::TokenPayload`; parked at 0.2.0 (HMAC only, TODO T12). If services later need hub-trusted tokens for machine calls, the planned direction is a `client_credentials` fetcher against the hub (TASK-024), not asymmetric signing in the gem. |
| `rack-jwt-verifier` | hub's own API and MCP endpoint; every downstream service | verifies bearer tokens against the hub's JWKS with mandatory `iss`/`aud`, scopes and replay guard. |
| `header_guard` | hub | HSTS, CSP (nonce-aware), frame/referrer/COOP/CORP/permissions headers. |
| `omniauth-ssoprovider` | client applications; hub test suite and developer page | the reference login client — defines the contract the hub must honour (`/oauth/authorize`, `/oauth/token`, `/api/v1/userinfo`). |
| `omniauth_syncer` | client applications only | syncs the auth hash into the client's local user model; not used by the hub. |

## 5. Decisions log

| Date | Decision | Why | Revisit when |
|---|---|---|---|
| 2026-09-18 | The hub is the **provider**, not an OmniAuth client; the client strategy wiring was removed (TASK-005). | Audit E5: the app was wired as a consumer of itself. | — |
| 2026-09-18 | RSpec is the canonical test suite; `test/` is to be removed (TASK-008). | Matches `harness.yaml`; the Minitest files could not run. | — |
| 2026-09-18 | Deployment target: Docker on a single host. | Only Dockerfile/compose exist; keeps infra advice concrete. | Scaling beyond one host. |
| 2026-09-18 | Licensing / tenancy / fine-grained authorization are a separate service. | Keeps the hub small and auditable (see §3). | — |
| 2026-09-18 | **Authorization-server core: Doorkeeper + doorkeeper-openid_connect**, behind the app's service layer; own gem left open (TASK-003). | Audit §5.4: an AS is the wrong thing to hand-roll first; Doorkeeper is mature and audited. | When the service layer is stable and an own gem would add real value (e.g. MCP-native features). |
| 2026-09-18 | **Access tokens are RS256 JWTs** issued through doorkeeper-jwt (claims in §3); id_tokens via doorkeeper-openid_connect; both signed by the hub's `SigningKey` (TASK-015). jwt_auth_client's HMAC/Issuable path left the hub entirely in TASK-019 (gem dropped from the Gemfile; nothing called it); rack-jwt-verifier is the verifier everywhere. (TASK-012) | Offline verification with a public key is the secure, future-proof default; opaque tokens would force every service to call introspection. | If a resource server needs instant revocation, it introspects (TASK-022). |
| 2026-09-18 | **Shared cache backend: Redis** (rate limiting, replay guard, later jobs). (TASK-012) | Proven atomic counters/TTLs; one extra compose service. | If operating Redis proves a burden, Solid Cache is the fallback. |
| 2026-09-18 | **Dynamic client registration is approval-gated** by default, behind a policy switch (`OAUTH_REGISTRATION_POLICY` approval/open/closed) so open mode can be enabled later. (TASK-012, TASK-025) | Safe default for a security product; MCP clients can still self-onboard pending approval. | When agent onboarding friction matters more than manual review. |
| 2026-09-18 | **Ruby/Rails upgrade (Ruby 3.4, Rails 8.x) is the first Phase 1 task** (TASK-013). | EOL runtime + ~75 advisories; fewer moving parts before Doorkeeper. | — |
| 2026-09-18 | **Refresh tokens rotate immediately** (no `previous_refresh_token` column) and have an **absolute lifetime** from the authorization code; **reuse revokes the (user, client) family**, a **replayed code revokes its descendants** (TASK-019). | Doorkeeper's deferred revocation only fires through its own bearer lookup, which the hub never uses; OAuth 2.1 §4.3.1 / RFC 6749 §4.1.2. | If a client cannot cope with strict rotation (concurrent refreshes), a short grace window would need the column back plus an explicit revocation hook. |
| 2026-09-27 | **Revocation/introspection policy** (TASK-022): another client's token is refused with **403** (not a silent 200); **introspection is a scope** (`introspect`, machine), not a per-client flag, and needs client authentication; **password change/reset and admin disable sign the user out everywhere**, a **failed-attempts lock does not**. | RFC 7009 §2.1 says refuse and inform; one scope flag also serves TASK-024's machine clients; a lock can be triggered by anyone typing wrong passwords, so revoking on it would be a sign-out DoS. | If lockout becomes admin-driven or rate limiting (T24) makes brute-force locks rare, revisit revoking on lock; lockout thresholds become configurable in T55. |
| 2026-10-02 | **Machine grant** (TASK-024): confidential, approved clients and machine-flagged scopes only (no `machine_scopes` column); earlier machine tokens stay live on reissue; **introspection stays client-authenticated**: a machine token with `introspect` is not accepted as a Bearer caller credential. | One scope flag already says what a service may hold; a service may hold two tokens during rollover; client authentication is the mainstream introspection guard (RFC 7662 §2.1), and a leaked Bearer token would become a token-scanning oracle. | If a deployment needs workers that never hold the client secret (a gateway fetching tokens for them), revisit a Bearer path limited to machine tokens carrying `introspect`. |
| 2026-10-02 | **Email over generic SMTP from env** (`SMTP_ADDRESS`/`PORT`/`USERNAME`/`PASSWORD`, `MAILER_FROM`), no vendor gem (Phase 1 gate, TASK-026; implemented in TASK-030). | Works with any provider or a local relay, no lock-in, no new dependency; self-hosting stays simple. | If deliverability needs bounce webhooks or provider-specific features. |
| 2026-10-02 | **Production TLS: Caddy** in `docker-compose.prod.yml` (TASK-026; implemented in TASK-033). | Automatic Let's Encrypt certificates and renewal with a ten-line config — the simplest secure default on one Docker host. | If more services share the host (Traefik) or the operator brings their own proxy. |
| 2026-10-02 | **Token confidentiality options split** (TASK-026, from T57): Phase 2 adds an env switch to keep `name`/`email` out of access tokens (T60, TASK-036); **DPoP** (RFC 9449) arrives with the MCP endpoint in Phase 4 (T61), where the hub is issuer and resource server; JWE and mTLS-bound tokens stay in Future. Product goal (user): stand out on MCP functionality, ease of use, security and configurable options. | Claim minimisation is cheap and immediate; DPoP only pays off once resource servers verify proofs; JWE needs per-resource keys and gem work. | When a deployment needs encrypted claims or certificate-bound service tokens. |
| 2026-10-02 | **Phase 2 re-plan** (TASK-026): rate limiting with Rails 8 `rate_limit` on the shared Redis cache instead of rack-attack; authorization-code single-use dropped from the Redis row (already enforced in the database, TASK-019 — audit §5.2 corrected); rack-jwt-verifier's `jti` replay cache is to be verified before use, because bearer access tokens are legitimately reused for their lifetime; T56 waits in Phase 3 for the omniauth-ssoprovider fix (T44); RFC 7592 (T59) moves to Phase 4. | Fewer dependencies; the audit's assumptions checked against the Phase 1 code (docs/PHASES.md). | At the Phase 2 gate (TASK-037). |
| 2026-10-02 | **Redis is `Rails.cache`** in production and development (`redis_cache_store` from `REDIS_URL`; production refuses to boot without it), an in-memory store in test; `redis` gem 5.x; **rack-jwt-verifier's `replay_cache` stays off** (TASK-027). | Rate-limit counters and readiness must agree across Puma workers and hosts; any Redis-protocol server works (compose runs `redis:7`, production picks its image in TASK-033). The replay guard allows one use per `jti`, which bearer tokens reused for their 10-minute life cannot satisfy; revocation is checked per request in the database instead. | Move to `redis` 6 once its RESP3 default has settled; enable a replay guard only for one-time tokens (DPoP proofs, T61). |

## 6. Future directions (not scheduled)

- **Multiple realms (Keycloak-style).** Isolated user pools with their own clients, consents,
  signing keys, branding and issuer (`https://hub.example/realms/<name>`), administered separately.
  Not planned for Phases 1–4, but Phase 1 code must not preclude it: one implicit *default* realm,
  issuer and keys resolved through a single accessor rather than global constants, no schema that
  assumes exactly one tenant. Adding realms later then means a `realms` table, a realm foreign key
  on users/clients/consents/keys, realm-scoped routes and discovery documents.
- **Kubernetes deployment.** The decided target for now is Docker on a single host (§5). A later
  move to Kubernetes (manifests or a Helm chart; liveness/readiness probes; HPA on the web
  deployment; secrets from the cluster's secret store or an external KMS; managed Postgres/Redis)
  needs nothing the app does not already plan: 12-factor env-only config, the readiness endpoint
  and JSON logs from T29, stateless web processes (cookie sessions, shared state in Redis), signing
  keys injected as secrets with rotation via the PREVIOUS key (TASK-015). Keep the Dockerfile and
  compose files the single source of runtime truth so a chart can be derived from them.
- **Own authorization-server gem** replacing Doorkeeper behind the service layer (§4).
- **Open dynamic registration** by flipping `OAUTH_REGISTRATION_POLICY` (TASK-025).
- **Federation** (the hub as a client of upstream identity providers) — that is where
  `omniauth_syncer` would come back into the hub.

