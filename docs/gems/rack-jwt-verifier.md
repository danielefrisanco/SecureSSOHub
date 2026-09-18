# rack-jwt-verifier — handover prompt (0.3.0 → 0.4.0)

Paste this whole file into a Claude session opened in the `rack_jwt_verifier`
repository (`../rack_jwt_verifier`, last commit `963974a`, version 0.3.0).

---

## Who is asking and why

I maintain `rack-jwt-verifier`, a Rack middleware that verifies bearer JWTs
(JWKS / PEM / HMAC key sources, `iss`/`aud` mandatory, `require_scopes`,
`replay_cache`, `skip`, JSON errors). I also build **SecureSSOHub**, an OAuth
2.1 / OpenID Connect authorization server (Rails 8.1, Doorkeeper 5.9 +
doorkeeper-openid_connect + doorkeeper-jwt) that issues RS256 access tokens.
The hub is now the first real consumer of this gem: it protects its own
`/api/**` with it, and every downstream service that trusts the hub will use
it unchanged. Wiring it into the hub exposed four gaps. Two matter now (one is
a security fix), two are for the hub's upcoming MCP endpoint.

The hub repository is `../SecureSSOHub`. The files named below are there.
Do not modify the hub from this session; the hub gets a version bump once the
gem is released.

## What the hub emits (the contract you are verifying)

Access tokens are RS256 JWTs per RFC 9068. Header: `kid` (RFC 7638 thumbprint
of the signing key), `typ: "at+jwt"`, `alg: "RS256"`. Payload
(`docs/ARCHITECTURE.md` §3, built by `app/services/oauth/token_payload.rb`):

| claim | value |
|---|---|
| `iss` | the hub issuer URL (`HUB_ISSUER`, e.g. `https://hub.test`) |
| `sub` | the user's `sso_id`; the client's `client_id` for client-credentials tokens |
| `aud` | the RFC 8707 `resource` of the authorization request, else the client's `client_id` |
| `azp` | the client the token was issued to |
| `scope` / `scopes` | space-delimited string **and** array |
| `jti` | UUID, unique per token |
| `iat`, `nbf`, `exp` | `nbf` = `iat`, `exp` = `iat` + 600 s |
| `name` | only with the `profile` scope |
| `email`, `email_verified` | only with the `email` scope |
| `admin` | boolean |

The hub also issues **id_tokens** (OIDC, `openid` scope) signed with the same
key: header `kid` and `typ: "JWT"`, payload `iss` (same), `sub` (same),
`aud` = `client_id`, `nonce`, `auth_time`, `at_hash`, `exp`, `iat`, plus
`name`/`email` with the scopes. They carry **no** `scope`/`scopes` claim.

JWKS at `GET {issuer}/.well-known/jwks.json`: `{ "keys": [ { kty, n, e, kid, use: "sig", alg: "RS256" }, … ] }`.
During a rotation it lists two keys (active + previous); tokens signed with
either must verify. Cache headers are set; the document is public.

## How the hub uses the gem today, including the workaround

`config/initializers/rack_jwt_verifier.rb` in the hub:

```ruby
Rails.application.config.middleware.insert_before(
  Warden::Manager,
  RackJwtVerifier::Middleware,
  skip: [outside_api],                       # callable: everything except /api and /api/**
  public_key: active_public_key,             # PLACEHOLDER: satisfies "exactly one key source"
  algorithms: %w[RS256],
  decode_options: {
    iss: issuer,
    aud: "#{issuer}/api",
    leeway: 30,
    jwks: ->(_options) { OAuth::SigningKey.for(realm: :default).jwks }   # the real key set
  },
  require_token: true,
  json_errors: true
)
```

The hub verifies **its own** tokens, so it must never fetch its JWKS over HTTP
from itself, and during a rotation it has two public keys. Neither `public_key`
(exactly one key, no `kid` selection) nor `jwks_url` (always fetches) fits. The
hub therefore passes its JWKS as the ruby-jwt `jwks` decode option, which
ruby-jwt prefers over the positional key (`JWT::Decode#set_key`, jwt 2.10.3
`lib/jwt/decode.rb:61-66`), next to a placeholder `public_key`. It works, it is
spec'd, and it relies on an undocumented pass-through that a future gem or
ruby-jwt change could silently break. That is TODO T48.

## Requested changes

### 1. In-process key-set source (`jwks:` option) — TODO T48, medium

Add a fifth key source to `Verifier::KEY_SOURCE_OPTIONS`, mutually exclusive
with the other four like today: `jwks:`. Accept, in order of usefulness:

- a callable (`#call`) returning a JWKS: called on every verification with the
  same `options` hash ruby-jwt passes to a JWKS loader (`kid_not_found:`,
  `invalidate:`), so the caller can refresh on those signals; the gem must not
  cache the result across calls (the caller owns freshness);
- a `Hash` JWKS document (string or symbol keys) or a `JWT::JWK::Set`: parsed
  once at boot, immutable;
- optionally an `Array` of PEM strings / `OpenSSL::PKey` (each converted to a
  JWK with a thumbprint `kid`), for operators who hold public keys rather than
  a JWKS.

Semantics:

- `KeySource::InProcessJwks` (or similar) answers `jwks? == true`, exposes
  `jwks_loader` in the shape `Verifier#decode` already consumes, and `refresh!`
  returns `false` for static input and `true` for a callable (delegating the
  `invalidate: true` signal to it). Keep the existing `decode_with_rotation`
  retry on `JWT::VerificationError`.
- Validate at boot: an empty key set, a set without `kid`s when more than one
  key is present, or a callable that raises on its first call must raise
  `ConfigurationError` with a message that names the option.
- Selection is by `kid`; a token whose `kid` is not in the set must fail as
  `invalid_token` (it does today via `JWT::JWK::KeyFinder`); a token without
  `kid` against a multi-key set must also fail.
- Refuse `decode_options[:jwks]` and `decode_options[:key]` with a
  `ConfigurationError` that points to the `jwks:` option. The hub is the only
  known user of that pass-through and will switch at the version bump; failing
  loudly is better than two ways to do one thing. (If you prefer a deprecation
  warning for one minor version, say so in the CHANGELOG and make it an error
  in the next.)
- README: a "Verifying your own tokens / in-process key set" section with the
  hub's use case (an authorization server guarding its own API) and the
  rotation story (two keys in the set, `kid` selection, no fetch).

### 2. RFC 9068 `typ` check (`require_typ:` option) — TODO T52, **high, security**

Found while spec'ing the hub's API: an **id_token** issued by the hub has the
hub's `iss`, is signed by the same key, and for a client whose access tokens
carry `aud = client_id` (no `resource` indicator) also has the `aud` that a
downstream service configured with `aud: <client_id>` expects. It carries no
`scope`, so `require_scopes` would catch it *if the service requires any
scope*; a service that only checks `iss`/`aud` accepts an id_token as a bearer
credential. The only reliable discriminator is the JOSE header `typ`
(`"at+jwt"` for access tokens, RFC 9068 §2.1; `"JWT"` for id_tokens).

Add `require_typ:` (String, or Array of Strings). When set:

- compare against the token header's `typ` **case-insensitively**, accepting
  both the bare media subtype and the `application/` prefixed form, as RFC
  8725 §3.11 / RFC 9068 §4 require (`"at+jwt"` matches `"AT+JWT"` and
  `"application/at+jwt"`);
- a missing or non-matching `typ` is an `invalid_token` (401) with an
  `error_description` that names the expected type; log it like other rejections;
- the check runs after signature verification, before the replay guard
  (`Verifier#verify` currently discards `_header` from `JWT.decode`; keep it).

Default: **unset** (no check), because the gem also verifies tokens that
carry no `typ` (jwt_auth_client's HMAC tokens, many third-party providers).
But the README must recommend `require_typ: "at+jwt"` for any OAuth 2
resource server, with this exact confusion scenario as the reason, and the
gem's own error message for a missing `typ` should mention the option.

Also expose the verified header alongside the payload, e.g.
`env["rack_jwt_verifier.header"]` (constant next to `RACK_ENV_PAYLOAD_KEY`),
so applications can read `kid`/`typ` without decoding again.

### 3. RFC 9728 `resource_metadata` in the challenge — TODO T40, medium

The hub's MCP endpoint (Phase 4) must answer an unauthenticated request with
`401` and `WWW-Authenticate: Bearer resource_metadata="https://hub/.well-known/oauth-protected-resource"`
(RFC 9728 §5.1) so MCP clients discover the authorization server. Add an
option `resource_metadata:` (absolute https URL, validated at boot). When set,
every `Bearer` challenge the middleware emits (missing token, invalid token,
insufficient scope) appends `, resource_metadata="<url>"` (after `error`,
`error_description`, `scope` if present; a plain `Bearer resource_metadata="…"`
for the missing-token case). Quote and sanitise it like `error_description`.

### 4. `current_token` helper — TODO T40, medium

Applications keep re-implementing "read the payload from env, pull `sub`,
scopes, client id, expiry". Provide a small value object and a Rails-free
accessor:

```ruby
token = RackJwtVerifier.token(env)          # => RackJwtVerifier::Token or nil
token.claims      # the payload Hash
token.header      # the JOSE header Hash (from change 2)
token.subject     # claims["sub"]
token.client_id   # claims["azp"] || claims["client_id"]
token.scopes      # RackJwtVerifier::Scopes.from(claims)
token.scope?(*s)  # Scopes.include?
token.jti, token.audience, token.issuer, token.expires_at (Time)
```

Plus an opt-in Rails/ActionController mixin (`require "rack_jwt_verifier/rails"`,
never auto-required) with `current_token` and `require_scope!(*scopes)` that
renders the same 403 `insufficient_scope` challenge the middleware does. Keep
the core gem free of any Rails dependency.

### 5. Path normalisation of `skip` rules — small, found in the hub review

The middleware matches `skip` String/Regexp rules against the raw
`SCRIPT_NAME + PATH_INFO`. Rails' router (Journey) squeezes repeated slashes
and drops a trailing slash before routing, so `//api/v1/userinfo` is served as
`/api/v1/userinfo`. The hub's *inverted* skip predicate ("skip everything
except /api") let `//api/...` through unguarded until the hub normalised the
path itself (`ActionDispatch::Journey::Router::Utils.normalize_path`). Do the
equivalent in the gem before evaluating skip rules: collapse `/+` to `/` and
strip one trailing slash (do **not** decode percent-escapes or resolve dot
segments; the router does not either). Document that skip rules see the
normalised path. This is a behaviour change worth a CHANGELOG line.

## Tests to add (RSpec, in this repo)

Extend `spec/rack_jwt_verifier/verifier_spec.rb`, `middleware_spec.rb` and the
`spec/support/token_factory.rb` helper:

- `jwks:` as callable: verifies with key A; after the callable starts returning
  B and a token signed with B arrives (`kid_not_found`), it verifies; a token
  with an unknown `kid` is `invalid_token`; the callable is invoked per
  verification, never cached; a callable raising at boot → `ConfigurationError`.
- `jwks:` as Hash / `JWT::JWK::Set` / Array of PEMs: two-key set selects by
  `kid`; empty set → `ConfigurationError`; combined with `public_key` or
  `jwks_url` → `ConfigurationError`; `decode_options: { jwks: … }` →
  `ConfigurationError`.
- `require_typ: "at+jwt"`: accepts `at+jwt`, `AT+JWT`, `application/at+jwt`;
  rejects missing `typ`, `JWT`, `id+jwt` with 401 and a challenge naming the
  expected type; the id_token confusion scenario reproduced end to end
  (same key, same `iss`, `aud` = client id, no scopes, `typ: "JWT"` → 401 with
  `require_typ`, 200 without it).
- `env["rack_jwt_verifier.header"]` is set on success and absent on refusal.
- `resource_metadata:`: present in the missing-token, invalid-token and
  insufficient-scope challenges with correct quoting; rejected at boot when not
  an absolute https URL.
- `RackJwtVerifier.token(env)` and the Rails mixin (use a bare
  `ActionController::API` subclass in a spec with `action_controller` as a
  development dependency only).
- Skip normalisation: `"/health"` skips `//health` and `/health/`; a Regexp
  rule sees the normalised path; a callable still receives the raw env.

Keep the existing `spec/rack_jwt_verifier/interop_spec.rb` green.

## Docs, versioning, release

- Version `0.4.0` (new options; one behaviour change in `skip`). Ruby ≥ 3.1,
  `jwt >= 2.8, < 4`, `rack >= 2.2, < 4` unchanged. If jwt 3.x changed the JWKS
  loader signature or `JWT::JWK::Set`, guard it and add it to the CI matrix.
- CHANGELOG entries for each of the five points; README sections: "In-process
  key set", "Token type (`require_typ`)" with the confusion scenario, "MCP /
  protected resource metadata", "Reading the token in your app", "Skip rules".
- Rubocop clean, full suite green, `gem build` clean.

## Verifying against the hub before release

```bash
# in ../SecureSSOHub, temporarily:
#   Gemfile: gem "rack-jwt-verifier", path: "../rack_jwt_verifier"
bundle install
POSTGRES_HOST=localhost bundle exec rspec spec/requests/api
```

`spec/requests/api/rack_jwt_verifier_interop_spec.rb` runs the gem as shipped
in a standalone Rack app against real hub tokens (JWKS over WebMock `to_rack`,
and `public_key` mode). `spec/requests/api/v1/userinfo_spec.rb` covers the
hub's own mount, including the previous-key rotation case and the "id_token
presented as bearer" case (which today passes only because the hub's API
audience differs from the client id, i.e. the T52 scenario is real but not
triggered there). Both files must stay green with the new gem, with the
hub's initializer still on the pass-through. Then, as a separate check, edit
the hub initializer locally to use `jwks: -> { … }` and
`require_typ: "at+jwt"` and run the same specs; that edit is what the hub's
version-bump task will commit.

## Definition of done

- The five changes above implemented, spec'd, documented, released as 0.4.0.
- A short note back to the hub listing: the final option names, whether the
  `decode_options[:jwks]` pass-through raises or warns, and anything in the
  hub's token contract you found awkward to verify (that feeds the hub's
  TODO.md).
