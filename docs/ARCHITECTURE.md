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
  | `admin` | boolean, `true` only for administrators |

  Nothing else about the user is placed in an access token. The same scope gating applies to the
  id_token (`openid` scope; `sub`, `iss`, `aud` = client_id, `nonce`, `auth_time`, `at_hash`) and to
  userinfo. Refresh tokens are opaque, hashed at rest, issued only with `offline_access`.
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

**Role of each self-developed gem in the target architecture**

| Gem | Where | Role |
|---|---|---|
| `jwt_auth_client` | services calling each other (not the hub today) | service → service calls with `HttpClient`. Removed from the hub in TASK-019: access tokens are minted by doorkeeper-jwt + `OAuth::TokenPayload`; it returns only if the hub itself calls services with signed requests (then with asymmetric signing, 0.3.0). |
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

