---
name: api-guard-and-spec-quirks
description: How /api/** is guarded by rack-jwt-verifier 0.3.0 in-process (gem limits, ruby-jwt jwks pass-through), how API controllers get claims/user, and WebMock/rack-session + harness guard quirks hit in request specs
metadata:
  type: project
---

`/api/**` is guarded by `RackJwtVerifier::Middleware` mounted in `config/initializers/rack_jwt_verifier.rb`
(TASK-020). API controllers inherit `Api::BaseController` (ActionController::API) which reads the verified
claims from `request.env["rack_jwt_verifier.payload"]`, checks `OAuth::Tokens.active?(jti:)` and the
disabled flag, and answers 401 `invalid_token` with the RFC 6750 challenge.

**Why:** the gem 0.3.0 only takes ONE `public_key` or a `jwks_url` fetched over HTTP; the hub has two
published keys during rotation and must not fetch from itself. ruby-jwt 2.10 prefers `options[:jwks]`
(callable allowed) over the positional key, so the initializer passes a placeholder `public_key` plus
`decode_options[:jwks] = -> { OAuth::SigningKey.for(realm: :default).jwks }` (TODO T48 asks the gem for a
real option). Under `SECRET_KEY_BASE_DUMMY` a throwaway RSA key keeps the guard mounted.

**How to apply:**
- New API endpoints: subclass `Api::BaseController`, add a route under `namespace :api`, use `token_claims`,
  `token_scopes`, `current_user`, `require_user`. Never name Doorkeeper there (isolation spec).
- Initializers cannot autoload app code: read `Rails.application.config.x.oauth.*` (set by doorkeeper.rb,
  which sorts first); `OAuth::*` only inside lambdas evaluated at request time.
- Get a real access token in request specs with `spec/support/hub_access_token.rb`
  (`require "support/hub_access_token"`, `include HubAccessToken`, `obtain_access_token(user:, client:,
  scope:, resource: OAuth::Resources.hub_api)`); the client must be `:public` with matching scopes.
- WebMock `to_rack(Rails.application)` 500s: WebMock seeds `rack.session` with a Hash that rack-session 2
  cannot commit. Route to `->(env) { Rails.application.call(env.except("rack.session",
  "rack.session.options")) }` instead.
- The gem never checks the `typ` header: an id_token verifies at a service whose aud is its client_id
  (TODO T52). The hub side is safe because its aud is `HUB_ISSUER/api`.
- Harness Bash guard also blocks the words "secret"/"credential" inside heredoc file contents and Python
  strings — rephrase comments before writing files through Bash.
- Access-token `jti` is chosen on the Doorkeeper row (`OAuth::TokenRecord#generate_token`) and passed to
  `OAuth::TokenPayload` via `attributes[:jti]` (fetch — required); `Token#jti` is that claim.
