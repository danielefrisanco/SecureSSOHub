require "base64"
require "jwt"
require "openssl"

# OAuth 2.1 / OIDC core. Doorkeeper stays behind app/services/oauth (see
# docs/ARCHITECTURE.md §4 and spec/architecture/doorkeeper_isolation_spec.rb);
# this file and doorkeeper_openid_connect.rb are the only configuration points.
#
# --- Signing keys -----------------------------------------------------------
# OIDC_SIGNING_KEY is the active RSA private key (PEM, or base64 of the PEM
# because .env files dislike newlines); OIDC_SIGNING_KEY_PREVIOUS, set during a
# rotation, stays published in the JWKS so older tokens still verify (runbook
# in README). Both are parsed and validated at boot here — initializers cannot
# use autoloaded code — and handed to OAuth::SigningKey through config.x.
#   - development/test without a configured key: an ephemeral in-memory key;
#   - any other environment without a key: boot failure — the hub never signs
#     with a key its operator did not provide;
#   - SECRET_KEY_BASE_DUMMY (asset precompile in the Docker build): no key at all.
oauth_key_material = lambda do |value|
  text = value.to_s.strip
  text = Base64.strict_decode64(text) unless text.start_with?("-----BEGIN")
  key = OpenSSL::PKey::RSA.new(text)
  raise "OIDC signing key must be an RSA private key of at least 2048 bits" if !key.private? || key.n.num_bits < 2048

  key.to_pem
end

signing_key_pems =
  if ENV["SECRET_KEY_BASE_DUMMY"]
    []
  elsif ENV["OIDC_SIGNING_KEY"].present?
    [oauth_key_material.call(ENV.fetch("OIDC_SIGNING_KEY")),
     ENV.fetch("OIDC_SIGNING_KEY_PREVIOUS", nil).presence&.then { |pem| oauth_key_material.call(pem) }]
  elsif Rails.env.local?
    [OpenSSL::PKey::RSA.new(2048).to_pem, nil]
  else
    raise "OIDC_SIGNING_KEY is not set: the hub refuses to boot without a token signing key"
  end
Rails.application.config.x.oauth.signing_key_pems = signing_key_pems

# One `kid` convention everywhere (id_tokens, access tokens, JWKS): RFC 7638.
JWT.configuration.jwk.kid_generator = JWT::JWK::Thumbprint

# Canonical https URL of the hub: `iss` of every token, base of the discovery
# document and of the hub's own resource identifiers (OAuth::Resources).
Rails.application.config.x.oauth.issuer =
  ENV.fetch("HUB_ISSUER") { Rails.env.local? ? "http://localhost:3000" : raise("HUB_ISSUER is not set") }

# Scope catalogue (config/oauth_scopes.yml); OAuth::Scopes wraps it for the app.
scope_catalogue = Rails.application.config_for(:oauth_scopes).fetch(:scopes)
Rails.application.config.x.oauth.scopes = scope_catalogue

# Absolute lifetime of a refresh token in seconds (OAuth::Tokens), counted
# from the authorization code it descends from — rotation does not extend it.
Rails.application.config.x.oauth.refresh_token_ttl =
  Integer(ENV.fetch("OAUTH_REFRESH_TOKEN_TTL", 30.days.to_i)).seconds

Doorkeeper.configure do
  orm :active_record

  # The resource owner is a Devise user; unauthenticated requests go to sign-in.
  resource_owner_authenticator do
    current_user || warden.authenticate!(scope: :user)
  end

  # Doorkeeper's own admin views are not mounted (Phase 3 builds ours), but the
  # block must exist and must never let a non-admin through.
  admin_authenticator do
    current_user&.is_admin || redirect_to(main_app.root_path)
  end

  # Tokens and client secrets are stored hashed; the plain value is shown once.
  hash_token_secrets
  hash_application_secrets

  access_token_expires_in 10.minutes
  authorization_code_expires_in 1.minute

  # A refresh token only comes with the `offline_access` scope (public clients
  # included: the code exchange was PKCE-bound). Rotation is immediate — the
  # used refresh token is revoked under a row lock — because the schema has
  # no `previous_refresh_token` column (db/migrate/20260918200000); reuse of
  # a rotated token and the absolute lifetime are OAuth::TokenRules.
  use_refresh_token do |context|
    Doorkeeper::OAuth::Scopes.from_string(context.scopes.to_s).exists?("offline_access")
  end

  grant_flows %w[authorization_code client_credentials]

  # Only approved clients (OAuth::ClientRules approval workflow) get a code or
  # a client_credentials token; pending and revoked ones are refused as
  # unauthorized_client. Codes and refresh tokens issued earlier are closed
  # by OAuth::TokenRules.
  allow_grant_flow_for_client { |_grant_flow, client| client.usable? }

  # PKCE: S256 is mandatory for public clients and honoured for confidential
  # ones; `plain` is never accepted. The public/confidential distinction and
  # the invalid_request wording live in OAuth::AuthorizationRules; these two
  # settings keep Doorkeeper's own checks and the discovery document in line.
  force_pkce
  pkce_code_challenge_methods %w[S256]

  # Resource indicator (RFC 8707): validated by OAuth::AuthorizationRules,
  # stored on the grant and copied to the token, where it becomes `aud`
  # (OAuth::TokenPayload).
  custom_access_token_attributes [:resource]

  # RFC 6749 §4.1.2.1: once the client and redirect_uri are verified, errors
  # go back to the client; before that (bad client_id, bad redirect_uri) the
  # error page is rendered — never a redirect to an unverified URI.
  handle_auth_errors :redirect

  # Clients may only request scopes from the catalogue they were registered with.
  enforce_configured_scopes
  default_scopes(*scope_catalogue.select { |_, v| v[:default] }.keys)
  optional_scopes(*scope_catalogue.reject { |_, v| v[:default] }.keys)

  # The consent page is skipped when the user's standing consent for the
  # client (OAuth::Consents, TASK-018) already covers every requested scope.
  # Runs in the controller, so `pre_auth` is at hand.
  skip_authorization do |resource_owner, client|
    OAuth::Consents.covers?(user: resource_owner, client_uid: client.uid, scopes: pre_auth.scopes.to_a)
  end

  # The redirect-URI policy (https, http only on loopback, private-use schemes
  # for public clients) lives in OAuth::ClientRules and applies in every
  # environment; Doorkeeper's blanket https rule would refuse loopback http.
  force_ssl_in_redirect_uri false

  # Access tokens are RS256 JWTs (payload: OAuth::TokenPayload, wired below).
  access_token_generator "::Doorkeeper::JWT"
end

# The hub's client-registry rules (client type, approval workflow, redirect
# allow-list), authorization-request rules (PKCE, resource indicator, admin
# scopes), the disabled-account guard, the consent page and the token-endpoint
# rules (replay, refresh reuse and lifetime, id_token at_hash, last_used_at) —
# kept out of app/models and app/controllers so nothing there names
# Doorkeeper. Wired once, after boot (a to_prepare hook would re-register the
# validations on every code reload in development).
Rails.application.config.after_initialize do
  Doorkeeper::Application.include(OAuth::ClientRules)
  Doorkeeper::OAuth::PreAuthorization.prepend(OAuth::AuthorizationRules)
  Doorkeeper::AuthorizationsController.prepend(OAuth::AuthorizationGuard)
  Doorkeeper::AuthorizationsController.prepend(OAuth::ConsentScreen)
  Doorkeeper::OAuth::AuthorizationCodeRequest.prepend(OAuth::TokenRules)
  Doorkeeper::OAuth::RefreshTokenRequest.prepend(OAuth::TokenRules)
end

# Both blocks run per token, so the autoloaded OAuth::TokenPayload and
# OAuth::SigningKey own the claims and the key material.
Doorkeeper::JWT.configure do
  token_payload { |opts| OAuth::TokenPayload.build(opts) }
  token_headers { |_opts| OAuth::TokenPayload.headers }
  secret_key { |_opts| OAuth::SigningKey.for(realm: :default).private_key.to_pem }
  signing_method :rs256
end
