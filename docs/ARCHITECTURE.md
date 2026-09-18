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

## 4. Decisions log

| Date | Decision | Why | Revisit when |
|---|---|---|---|
| 2026-09-18 | The hub is the **provider**, not an OmniAuth client; the client strategy wiring was removed (TASK-005). | Audit E5: the app was wired as a consumer of itself. | — |
| 2026-09-18 | RSpec is the canonical test suite; `test/` is removed. | Matches `harness.yaml`; the Minitest files could not run. | — |
| 2026-09-18 | Deployment target: Docker on a single host. | Only Dockerfile/compose exist; keeps infra advice concrete. | Scaling beyond one host. |
| 2026-09-18 | Licensing / tenancy / fine-grained authorization are a separate service. | Keeps the hub small and auditable (see §3). | — |
