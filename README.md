# Secure SSO Hub

A Ruby on Rails application that acts as a central Single Sign-On (SSO) provider: it owns the
user accounts (Devise), authenticates people, and issues signed JWTs that client applications and
services trust. The target architecture — an OAuth 2.1 / OpenID Connect authorization server with an
MCP endpoint for agents — is described in [`docs/ARCHITECTURE.md`](docs/ARCHITECTURE.md); the
current-state audit is in [`docs/AUDIT.md`](docs/AUDIT.md) and the backlog in [`TODO.md`](TODO.md).

## Building blocks

| Concern | Implementation |
|---|---|
| Framework | Rails 8.1, Ruby 3.4.10, PostgreSQL 17 |
| User accounts | [Devise](https://github.com/heartcombo/devise) |
| Identity | each user has a stable `sso_id` (UUID) used as the token subject, decoupled from the email |
| Token issuing | [`jwt_auth_client`](https://rubygems.org/gems/jwt_auth_client) (`Issuable` mixin on `User`) |
| Token verification on the hub's own API | [`rack-jwt-verifier`](https://rubygems.org/gems/rack-jwt-verifier) |
| Security headers / CSP | [`header_guard`](https://rubygems.org/gems/header_guard) |
| Reference client (tests, docs) | [`omniauth-ssoprovider`](https://rubygems.org/gems/omniauth-ssoprovider) |

## The SSO flow

1. A client application redirects the user to the hub's authorization endpoint.
2. The hub authenticates the user with Devise (and asks for consent).
3. The client exchanges the authorization code for a signed JWT at the token endpoint.
4. The client verifies the token (via the hub's JWKS) and establishes its own session.

The endpoints are being built phase by phase; see `TODO.md` for what exists today.

## Development

```bash
docker compose up -d db                      # PostgreSQL 17 on localhost:5432
bundle install
DATABASE_URL=postgres://postgres:<password>@localhost:5432/secure_sso_hub_test \
  bin/rails db:prepare                       # <password> = POSTGRES_PASSWORD from docker-compose.yml
bundle exec rspec
```

Or run everything in containers with `docker compose up --build`.

## Configuration

All configuration comes from environment variables; there are no fallback values for secrets.

| Variable | Purpose |
|---|---|
| `DATABASE_URL` / `SECURE_SSO_HUB_DATABASE_PASSWORD` | database connection |
| `JWT_SERVICE_SECRET` | token signing key, at least 32 bytes — `openssl rand -hex 32` (HMAC until asymmetric keys land); required to boot |
| `JWT_ISSUER` | `iss` claim of tokens minted by jwt_auth_client (default `secure-sso-hub`; legacy, removed in TASK-019) |
| `HUB_ISSUER` | canonical https URL of this hub, e.g. `https://sso.example.com` — the OAuth/OIDC `iss` and the base of every discovery URL; required outside development/test |
| `OIDC_SIGNING_KEY` | active RSA private key (≥ 2048 bits) that signs access and id tokens — PEM, or the PEM base64-encoded on one line; required outside development/test (an ephemeral key is generated there) |
| `OIDC_SIGNING_KEY_PREVIOUS` | the previous signing key during a rotation (same format); stays published in the JWKS so tokens it signed still verify |

### Key rotation

Every token carries the `kid` (RFC 7638 thumbprint) of the key that signed it; clients and resource
servers verify against `https://<hub>/.well-known/jwks.json`, which lists the active key and, during a
rotation, the previous one.

```bash
bin/rails hub:keys:generate     # prints a new key as OIDC_SIGNING_KEY=<base64 PEM> plus its kid
bin/rails hub:keys:show         # kids of the keys the running app has loaded
```

1. Generate a new key. Set `OIDC_SIGNING_KEY_PREVIOUS` to the *current* value and `OIDC_SIGNING_KEY`
   to the new one; deploy. New tokens are signed with the new key; the JWKS lists both.
2. Wait at least the longest token lifetime (refresh tokens included) plus the clients' JWKS cache
   TTL (5 minutes by default).
3. Remove `OIDC_SIGNING_KEY_PREVIOUS`; deploy. The old key disappears from the JWKS.
| `RAILS_MASTER_KEY` | Rails credentials |

## Task workflow

This repository uses the harness plugin: `tasks/` holds the task files, `.harness/rules/` the
rules, and `.harness/progress.md` the log. See `CLAUDE.md`.
