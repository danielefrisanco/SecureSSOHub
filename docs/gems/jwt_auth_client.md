# jwt_auth_client — handover prompt (0.2.0, decision first)

Paste this whole file into a Claude session opened in the `jwt_auth_client`
repository (`../jwt_auth_client`, last commit `a1aa5e3`, version 0.2.0).
Priority: low. The first job is a decision, not code.

---

## Who is asking and why

I maintain `jwt_auth_client`: `TokenIssuer` (HS256/384/512 JWTs with `iss sub
aud scopes iat nbf exp jti`), the `Issuable` model mixin (`#to_jwt` driven by
`#jwt_claims`), `HttpClient` (Faraday, mints a token per request) and boot-time
configuration validation. I also build **SecureSSOHub** (`../SecureSSOHub`),
an OAuth 2.1 / OpenID Connect authorization server.

The hub was the gem's only known consumer. It **no longer uses it**: the hub
now issues RS256 access tokens through Doorkeeper + doorkeeper-jwt with its
own signing keys and published JWKS, and TASK-019 removed the `Issuable`
mixin, `jwt_claims`, the initializer, the `JWT_SERVICE_SECRET` variable and
the gem itself from the hub's Gemfile. The reason is architectural, not a bug
in the gem: a hub must sign with a private key and let everyone verify with a
public JWKS; a shared HMAC secret lets every holder mint tokens for every
audience (the gem's own README says so). This is TODO T12 (deferred) on the
hub side.

## What the hub emits now (the contract any service-side issuer should match)

If services mint their own tokens for service-to-service calls and want
`rack-jwt-verifier` deployments to treat them like hub tokens, the shape is
(`docs/ARCHITECTURE.md` §3 in the hub): RS256, header `kid` (RFC 7638
thumbprint) and `typ: "at+jwt"` (RFC 9068), claims `iss`, `sub`, `aud`,
`azp`, `scope` (string) **and** `scopes` (array), `jti` (UUID), `iat`, `nbf`,
`exp`. `rack-jwt-verifier` 0.4.0 (see `rack-jwt-verifier.md`) will offer
`require_typ: "at+jwt"`, so tokens without a `typ` header will be refused by
services that turn that on.

## The decision to make

Three honest options; pick one and record it in the gem's README/CHANGELOG:

1. **Park the gem.** Mark 0.2.0 as the final HMAC-only release, state in the
   README that an authorization server should not use it and point to the
   hub + `rack-jwt-verifier` pair. Cheapest; nothing depends on it today.
2. **0.3.0 asymmetric mode (the "planned" feature).** Keep the gem as the
   *service-side* token issuer for hub-less service-to-service calls, but
   make it produce tokens that verify exactly like hub tokens:
   - `algorithm: "RS256"` (and `ES256`) with a private key from configuration
     (PEM or `{ env: }`), `kid` = RFC 7638 thumbprint, header `typ: "at+jwt"`;
   - claims: add `azp` (= `iss` for a service token, or configurable),
     `scope` string next to the existing `scopes` array, keep `jti`/`nbf`;
   - a `JwtAuthClient::Jwks.document` helper that renders the public key(s)
     as a JWKS (with an optional previous key for rotation) so a service can
     serve `/.well-known/jwks.json` in three lines;
   - keep HMAC for backward compatibility but make the README steer to RS256;
   - `HttpClient` unchanged apart from the header (`typ`);
   - `Issuable` unchanged in interface;
   - specs: round trip through `rack-jwt-verifier` (development dependency)
     in `jwks:` mode with `require_typ: "at+jwt"`, key rotation (old `kid`
     still verifies while both keys are published), configuration validation
     for key material (private key required for signing; refuse a public key;
     refuse < 2048-bit RSA), thumbprint stability.
3. **Reposition as a verifier-side helper only** (no issuing): drop
   `TokenIssuer`/`Issuable`, keep `HttpClient` as a Faraday client that
   attaches a token obtained from the hub's `client_credentials` grant (the
   hub's TASK-024 adds that: `POST /oauth/token` with `grant_type=client_credentials`,
   Basic auth, optional `resource`, restricted machine scopes, 10-minute
   token, no refresh). That turns the gem into the "call another service on
   behalf of this machine client" piece and removes all key material from it.
   Specs against a WebMock'd token endpoint; token caching until `exp` minus
   leeway; one in-flight fetch per process.

My recommendation: option 3 if the hub's machine grant is the intended path
for service-to-service calls (it is the architecture the hub documents:
every token comes from the hub, every service verifies with the hub JWKS);
option 1 otherwise. Option 2 only if there is a concrete deployment that must
issue tokens without a hub.

## If option 2 or 3 is chosen

- Version 0.3.0; Ruby ≥ 3.1; `jwt >= 2.8, < 4`; rubocop; CHANGELOG; README
  rewritten around the chosen role.
- Verify against the hub: for option 3, run a WebMock'd spec against the hub's
  real token endpoint via `to_rack` once TASK-024 has landed
  (`spec/requests/oauth/machine_grant_spec.rb` in the hub shows the exact
  request/response); for option 2, run the hub's
  `spec/requests/api/rack_jwt_verifier_interop_spec.rb` pattern with a gem-minted
  token against a standalone `RackJwtVerifier::Middleware`.

## Definition of done

- The decision recorded in the gem (README + CHANGELOG), and, if 2 or 3,
  implemented, spec'd and released.
- A note back to the hub: which option, and whether the hub's TODO T12 row
  should be closed or rewritten.
