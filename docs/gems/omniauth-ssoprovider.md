# omniauth-ssoprovider — handover prompt (0.1.2 → 0.2.0)

Paste this whole file into a Claude session opened in the
`omniauth-ssoprovider` repository (`../omniauth-ssoprovider`, last commit
`3c25193`, version 0.1.2).

---

## Who is asking and why

I maintain `omniauth-ssoprovider`, an `OmniAuth::Strategies::OAuth2` subclass
(`lib/omniauth/strategies/ssoprovider.rb`) that logs a Rails app in against a
custom SSO server: authorize → token → `GET user_info_url` → `uid`/`info`/`extra`.
I also build **SecureSSOHub** (`../SecureSSOHub`), the OAuth 2.1 / OpenID
Connect server this strategy is meant to talk to. The hub now implements the
whole server side (authorization endpoint with mandatory PKCE, token endpoint
issuing RS256 JWTs and id_tokens, `/api/v1/userinfo`, JWKS) and its next task
(TASK-023) runs **this exact gem** end to end against the in-process hub as
the proof that the hub honours the contract its client gems expect.

Auditing the gem against the hub found one boot-breaking bug and a set of
gaps between what the strategy does and what an OAuth 2.1 / OIDC client
should do. This is TODO T44 on the hub side. Do not modify the hub from this
session.

## The server contract the strategy must honour (as the hub implements it)

Endpoints, relative to the hub issuer (`client_options.site`, e.g. `https://hub.test`):

- `GET /oauth/authorize` — parameters: `response_type=code`, `client_id`,
  `redirect_uri` (**exact** string match against the registered URI, no extra
  query, no trailing slash; only loopback `http://127.0.0.1`/`localhost` may
  vary the port), `scope` (space-delimited), `state`, `code_challenge` +
  `code_challenge_method=S256` (**mandatory for public clients, honoured for
  confidential ones; `plain` is always refused**), optional `nonce` (echoed
  into the id_token), optional `resource` (RFC 8707: the audience the access
  token is minted for; must be one the hub knows, else `invalid_target`).
  Errors after client and redirect_uri are verified come back to
  `redirect_uri` as `error`, `error_description`, `state`; errors before that
  are rendered by the hub (never redirected). Error codes the strategy will
  see on its callback: `access_denied` (user denied consent, or account
  disabled), `invalid_scope` (scope outside the client's registration or the
  catalogue, or a non-admin asking for `admin:*`), `unauthorized_client`
  (client pending approval or revoked), `invalid_request` (PKCE problems),
  `invalid_target`, `unsupported_response_type`.
- `POST /oauth/token` — `grant_type=authorization_code`, `code`,
  `redirect_uri`, `code_verifier`, client authentication: confidential clients
  via HTTP Basic (`client_secret_basic`, preferred) **or** body
  (`client_secret_post`); public clients send `client_id` only and **must not**
  send a secret (a public client presenting one is `invalid_client`). Response:
  `access_token` (RS256 JWT, 10 minutes), `token_type: "Bearer"`, `expires_in`,
  `scope`, `refresh_token` **only when `offline_access` was granted**, `id_token`
  **only when `openid` was granted**. `grant_type=refresh_token` rotates: the
  old refresh token is revoked immediately, a new pair is returned; presenting
  a rotated refresh token again revokes the whole family (`invalid_grant`).
  Codes are single-use and expire after 60 s; a replayed code is
  `invalid_grant` and revokes the tokens issued from it.
- `GET /api/v1/userinfo` with `Authorization: Bearer <access_token>` — the
  document this gem hard-codes. The access token must have been minted with
  `resource = {issuer}/api` (otherwise its `aud` is the client id and the hub
  API refuses it with 401). Body:

  ```json
  { "id": "<sso_id>", "sub": "<sso_id>", "name": "…", "email": "…",
    "email_verified": false, "roles": ["admin"] }
  ```

  `id`/`sub`/`roles` always; `name` only with the `profile` scope; `email` and
  `email_verified` only with the `email` scope; `roles` is `["admin"]` or `[]`.
- `GET /oauth/userinfo` — standard OIDC userinfo for the same token (`sub`,
  `name`, `email`, `email_verified` with the same scope gating).
- `GET /.well-known/jwks.json` — RSA public keys (`kid`, `use: "sig"`,
  `alg: "RS256"`; two keys during a rotation). `GET /.well-known/openid-configuration`
  and `/.well-known/oauth-authorization-server` arrive with the hub's TASK-021.

Access-token claims (RFC 9068, header `typ: "at+jwt"`, `kid`): `iss`, `sub`
(sso_id), `aud` (the `resource` or the client id), `azp` (client id),
`scope` + `scopes`, `jti`, `iat`, `nbf`, `exp`, `name`/`email`/`email_verified`
(scope-gated), `admin` (boolean). id_token claims: `iss`, `sub`, `aud` = client
id, `nonce`, `auth_time`, `at_hash`, `exp`, `iat`, `name`/`email` (scope-gated).

Scope catalogue: `openid`, `profile`, `email`, `offline_access`, `admin:clients`,
`admin:users`, `admin:tokens`, `admin:audit`, `introspect` (machine only).
A client may only request scopes it was registered with.

## Findings against 0.1.2

1. **Boot bug (blocks the README example).** `provider :ssoprovider, …` makes
   `OmniAuth::Builder` constantize `OmniAuth::Strategies::Ssoprovider`, but the
   class is `SSOProvider` and nothing registers the camelization.
   `config/initializers/omniauth.rb` from the README raises
   `LoadError: Could not find matching strategy for :ssoprovider`. The hub's
   integration spec must mount the strategy **by class** to work around it.
   The unused `OmniAuth.ssoprovider_strategy` helper in `lib/omniauth/ssoprovider.rb`
   does not help.
2. **No PKCE.** `omniauth-oauth2 ~> 1.8` supports `pkce: true` (S256 by default
   via `pkce_options`); the strategy does not enable it. The hub refuses public
   clients without S256 PKCE (`invalid_request`).
3. **No id_token handling.** The token response carries an `id_token` when
   `openid` is requested; the strategy ignores it, sends no `nonce`, and makes
   an extra HTTP round trip to `/api/v1/userinfo` for data the id_token already
   proves.
4. **No `resource` indicator.** Without it the access token's `aud` is the
   client id, so the strategy's `GET /api/v1/userinfo` gets 401 from a hub
   whose API audience is `{issuer}/api`. The strategy needs to send
   `resource={site}/api` by default (configurable) or read userinfo from
   `/oauth/userinfo`, which accepts the client-audience token.
5. **Default scope is unset.** `omniauth-oauth2` sends no `scope` unless
   configured; the hub then applies the client's default scopes, which may not
   include `profile`/`email`, so `info.name`/`info.email` come back `nil`.
6. **`uid` is `raw_info['id'].to_s`**: fine with the hub (`id` = `sub` = sso_id)
   but should fall back to `sub` (OIDC userinfo shape) so the strategy also
   works against `/oauth/userinfo`.
7. **`extra` exposes only `raw_info` and `access_token`**: no `refresh_token`,
   `expires_at`, `id_token` claims, `roles`, `email_verified`.
8. **Errors**: `raw_info` rescues `OAuth2::Error` only to re-raise it; a 401
   from userinfo should become an OmniAuth failure (`fail!(:invalid_credentials, e)`),
   not a 500.
9. **Spec suite** (`spec/omniauth/strategies/ssoprovider_spec.rb`) relies on a
   `strategy` helper that is "assumed from OmniAuth test helpers" and is not
   defined; the file does not run green. There is no request-level test of the
   callback phase.
10. **Packaging**: the README says `require: 'omniauth/strategies/ssoprovider'`;
    Bundler's default require for a gem named `omniauth-ssoprovider` is
    `omniauth-ssoprovider` (with the dash), which does not exist, so
    `gem "omniauth-ssoprovider"` without `require:` loads nothing.
    `required_ruby_version` spans `>= 2.7 < 4`; `omniauth-test ~> 0.0.11` is
    an odd dev dependency.

## Requested changes

1. Register the name: in `lib/omniauth/ssoprovider.rb`
   `OmniAuth.config.add_camelization "ssoprovider", "SSOProvider"`; add
   `lib/omniauth-ssoprovider.rb` that requires it, so both
   `gem "omniauth-ssoprovider"` and `provider :ssoprovider` work with no
   `require:` option. Drop `OmniAuth.ssoprovider_strategy`. Fix the README.
2. `option :pkce, true` (S256). Document that the hub, and OAuth 2.1 in
   general, require it; allow `pkce: false` only explicitly.
3. `option :scope, "openid profile email"` as the default; document
   `offline_access` (refresh token) and the `admin:*` scopes (admins only).
4. `option :resource, nil` → when set (default: `"#{site}/api"` **only if**
   `user_info_url` is the hub API path; otherwise nil), add `resource` to
   `authorize_params`. Document the RFC 8707 relationship between `resource`
   and the token's `aud`.
5. OIDC support:
   - generate a `nonce` per authorization (store in session like `state`),
     send it, and when the token response carries an `id_token`, verify it:
     signature against `{site}/.well-known/jwks.json` (fetch with `kid`
     selection, cache with a short TTL, refetch on unknown `kid`), `iss` =
     `site` (or an explicit `issuer` option), `aud` includes the client id,
     `nonce` matches, `exp`/`iat` with leeway; a failing id_token is an
     OmniAuth failure (`fail!(:invalid_id_token)`), never silently ignored;
   - expose the verified claims as `extra['id_token']` (claims Hash) and use
     `sub` as `uid` when present;
   - option `userinfo: true|false` (default true): with a verified id_token
     and `userinfo: false`, skip the HTTP call and build `info` from the
     id_token claims.
   Use `jwt` (`>= 2.8, < 4`) as a runtime dependency; do not add
   `rack-jwt-verifier` (it is a resource-server tool).
6. `info`: `name`, `email`, and add `email_verified` (top-level in OmniAuth's
   info schema is not standard, so put it in `extra`), plus `nickname` left
   nil. `extra`: `raw_info`, `access_token`, `refresh_token`, `expires_at`
   (Integer epoch), `id_token` (claims), `roles` (Array, `[]` default),
   `email_verified`.
7. `uid`: `raw_info['sub'] || raw_info['id']`, stringified.
8. Failure handling: wrap `raw_info` so a non-2xx from userinfo calls
   `fail!(:invalid_credentials, error)`; map the authorize-callback `error`
   parameter through `omniauth-oauth2`'s existing `CallbackError` (it already
   does `fail!(error, …)`; verify `access_denied`, `unauthorized_client`,
   `invalid_scope` reach `omniauth.error.type`). Document what each hub error
   means for the app.
9. Token endpoint authentication: keep `oauth2`'s default `auth_scheme:
   :basic_auth` (the hub prefers `client_secret_basic`); for public clients
   document `client_secret: nil` and make sure no empty Basic header is sent
   (verify how `oauth2` behaves with a nil secret; if it sends `Basic
   base64("id:")` the hub refuses it as `invalid_client`, so switch to
   `auth_scheme: :request_body` with only `client_id` when the secret is nil).
10. Spec suite, from scratch, green:
    - unit: defaults (`pkce`, `scope`, URLs), `authorize_params` contains
      `code_challenge`/`S256`/`nonce`/`resource`, `uid`/`info`/`extra` mapping
      from a hub-shaped userinfo document (with and without `profile`/`email`);
    - request phase and callback phase through `Rack::Test` +
      `OmniAuth::Builder` in a minimal Rack app with `Rack::Session::Cookie`,
      WebMock stubbing `/oauth/token`, `/api/v1/userinfo`, `/.well-known/jwks.json`
      with a real RSA key pair generated in the spec: happy path (auth hash as
      documented), tampered `state` → `csrf_detected`, `error=access_denied`
      → failure, bad id_token signature/nonce/aud → `invalid_id_token`,
      userinfo 401 → `invalid_credentials`;
    - a fixture builder that mints hub-shaped access tokens and id_tokens
      (claims listed above) so the specs stay aligned with the hub contract.
11. Packaging: `required_ruby_version >= 3.1`; drop `omniauth-test`; rubocop
    config; CHANGELOG; version 0.2.0. README rewritten around the hub flow:
    Rails setup (`provider :ssoprovider, id, secret, client_options: { site: }`),
    public vs confidential client, scopes, `resource`, what is in the auth
    hash, how to use `extra['access_token']` against a service protected by
    `rack-jwt-verifier`, refresh tokens (the strategy does not refresh; show
    the `oauth2` snippet), and the error table.

## Verifying against the hub

The hub's TASK-023 spec (`spec/integration/omniauth_ssoprovider_flow_spec.rb`,
to be written on the hub side) mounts the strategy in a minimal Rack client
app, routes the strategy's HTTP calls to the in-process hub with WebMock
`to_rack`, drives sign-in and consent with an integration session, and feeds
the code+state redirect back to the client callback. It asserts `uid ==
user.sso_id`, `info.name/email`, `extra.access_token` decodes with the hub
JWKS, and the negative flows (tampered state, denied consent, pending client).
Until this gem is released it mounts by class; after the release the hub bumps
the gem and switches to `provider :ssoprovider`.

To try the gem against the hub locally before releasing:

```ruby
# ../SecureSSOHub/Gemfile (test group, temporarily)
gem "omniauth-ssoprovider", path: "../omniauth-ssoprovider"
```

```bash
cd ../SecureSSOHub && bundle install && POSTGRES_HOST=localhost bundle exec rspec spec/integration
```

## Definition of done

- Findings 1–10 addressed, spec suite green, rubocop clean, README and
  CHANGELOG updated, 0.2.0 built.
- A note back to the hub with: the final option names and defaults
  (`pkce`, `scope`, `resource`, `userinfo`, `issuer`), how a nil client secret
  is sent to the token endpoint, and anything the hub does that made the
  client side awkward (feeds the hub's TODO.md).
