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
| Authorization server | [Doorkeeper](https://github.com/doorkeeper-gem/doorkeeper) + doorkeeper-openid_connect behind `app/services/oauth`; RS256 access tokens via doorkeeper-jwt (`OAuth::TokenPayload`) |
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
| `HUB_ISSUER` | canonical https URL of this hub, e.g. `https://sso.example.com` — the OAuth/OIDC `iss` and the base of every discovery URL; required outside development/test |
| `OIDC_SIGNING_KEY` | active RSA private key (≥ 2048 bits) that signs access and id tokens — PEM, or the PEM base64-encoded on one line; required outside development/test (an ephemeral key is generated there) |
| `OIDC_SIGNING_KEY_PREVIOUS` | the previous signing key during a rotation (same format); stays published in the JWKS so tokens it signed still verify |
| `OAUTH_REFRESH_TOKEN_TTL` | absolute lifetime of a refresh token in seconds, counted from the authorization code it descends from (default 2592000 = 30 days); access tokens live 10 minutes, codes 1 minute |
| `OAUTH_REGISTRATION_POLICY` | dynamic client registration (`POST /oauth/register`, RFC 7591): `approval` (default) — new clients wait for an administrator; `open` — public (PKCE) clients are usable at once; `closed` — no endpoint, not advertised in discovery. Any other value stops the boot |
| `OAUTH_REGISTRATION_IP_LIMIT` | registrations accepted per source address and hour (default 20); beyond it `429`. Behind a reverse proxy, configure Rails' trusted proxies so the client's address — not the proxy's — is counted |
| `RAILS_MASTER_KEY` | Rails credentials |

### Dynamic client registration

Clients — MCP agents above all — find `registration_endpoint` in the discovery documents and register
themselves with RFC 7591 metadata (`client_name`, `redirect_uris`, `token_endpoint_auth_method`: `none` for
a public PKCE client, `client_secret_basic`/`client_secret_post` for a confidential one, `scope`, …). A
confidential client receives its `client_secret` once, in the response. Registration never grants
`admin:*` or machine scopes, nor the machine grant; the same `client_name` with the same `redirect_uris`
is refused for 24 hours.

With the default `approval` policy the client is `pending`: it cannot sign anyone in or obtain tokens
until an administrator approves it. Until the admin UI exists (Phase 3), from a console:

```ruby
OAuth::Clients.list(state: :pending)   # review: name, redirect URIs, scopes, contacts, registration_ip
OAuth::Clients.approve("<client_id>", by: User.find_by!(email: "<admin email>"))
OAuth::Clients.revoke("<client_id>", by: User.find_by!(email: "<admin email>"))   # refuse (final)
```

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

## Task workflow

This repository uses the harness plugin: `tasks/` holds the task files, `.harness/rules/` the
rules, and `.harness/progress.md` the log. See `CLAUDE.md`.
