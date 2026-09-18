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
- Tokens carry `iss`, `aud` (resource indicator), `sub` (`sso_id`), `scopes`, `azp` (acting client),
  `exp`, `jti`. Resource servers must check `iss` and `aud` — `rack-jwt-verifier` refuses to boot
  without them.
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

**Role of each self-developed gem in the target architecture**

| Gem | Where | Role |
|---|---|---|
| `jwt_auth_client` | hub (and services calling each other) | signs tokens the hub issues (`Issuable` on `User`, `TokenIssuer` for the token endpoint claims until Doorkeeper's JWT layer takes over); hub → service calls with `HttpClient`. Needs asymmetric signing (0.3.0) to serve the JWKS. |
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
| 2026-09-18 | **Access tokens are RS256 JWTs** issued through doorkeeper-jwt (claims documented in §3 once TASK-019 lands); id_tokens via doorkeeper-openid_connect; both signed by the hub's `SigningKey` (TASK-015). jwt_auth_client's HMAC/Issuable path leaves the OAuth flow (kept for hub→service calls); rack-jwt-verifier is the verifier everywhere. (TASK-012) | Offline verification with a public key is the secure, future-proof default; opaque tokens would force every service to call introspection. | If a resource server needs instant revocation, it introspects (TASK-022). |
| 2026-09-18 | **Shared cache backend: Redis** (rate limiting, replay guard, later jobs). (TASK-012) | Proven atomic counters/TTLs; one extra compose service. | If operating Redis proves a burden, Solid Cache is the fallback. |
| 2026-09-18 | **Dynamic client registration is approval-gated** by default, behind a policy switch (`OAUTH_REGISTRATION_POLICY` approval/open/closed) so open mode can be enabled later. (TASK-012, TASK-025) | Safe default for a security product; MCP clients can still self-onboard pending approval. | When agent onboarding friction matters more than manual review. |
| 2026-09-18 | **Ruby/Rails upgrade (Ruby 3.4, Rails 8.x) is the first Phase 1 task** (TASK-013). | EOL runtime + ~75 advisories; fewer moving parts before Doorkeeper. | — |
