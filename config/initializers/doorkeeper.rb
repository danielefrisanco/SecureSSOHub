require "openssl"

# OAuth 2.1 / OIDC core. Doorkeeper stays behind app/services/oauth (see
# docs/ARCHITECTURE.md §4 and spec/architecture/doorkeeper_isolation_spec.rb);
# this file and doorkeeper_openid_connect.rb are the only configuration points.
#
# Signing key for access tokens (doorkeeper-jwt) and id_tokens (openid_connect).
# Placeholder until TASK-015 introduces SigningKey (kid, rotation, JWKS):
#   - OIDC_SIGNING_KEY (PEM) when present;
#   - an ephemeral in-memory key in development/test;
#   - a boot failure anywhere else — the hub never signs with a key it did not
#     get from its operator. The asset-precompile step of the Docker build boots
#     with SECRET_KEY_BASE_DUMMY and no configuration, so it gets no key at all.
signing_key_pem =
  if ENV["SECRET_KEY_BASE_DUMMY"]
    nil
  elsif ENV["OIDC_SIGNING_KEY"].present?
    OpenSSL::PKey::RSA.new(ENV.fetch("OIDC_SIGNING_KEY")).to_pem
  elsif Rails.env.local?
    OpenSSL::PKey::RSA.new(2048).to_pem
  else
    raise "OIDC_SIGNING_KEY is not set: the hub refuses to boot without a token signing key"
  end
Rails.application.config.x.oauth.signing_key_pem = signing_key_pem

# Scope catalogue (config/oauth_scopes.yml); OAuth::Scopes wraps it for the app.
scope_catalogue = Rails.application.config_for(:oauth_scopes).fetch(:scopes)
Rails.application.config.x.oauth.scopes = scope_catalogue

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
  use_refresh_token

  grant_flows %w[authorization_code client_credentials]

  # PKCE (S256) is mandatory for every authorization-code request.
  force_pkce

  # Clients may only request scopes from the catalogue they were registered with.
  enforce_configured_scopes
  default_scopes(*scope_catalogue.select { |_, v| v[:default] }.keys)
  optional_scopes(*scope_catalogue.reject { |_, v| v[:default] }.keys)

  force_ssl_in_redirect_uri !Rails.env.local?

  # Access tokens are RS256 JWTs (payload defined below; claims completed in TASK-019).
  access_token_generator "::Doorkeeper::JWT"
end

Doorkeeper::JWT.configure do
  token_payload do |opts|
    issued_at = Time.now.utc.to_i
    {
      sub: User.where(id: opts[:resource_owner_id]).pick(:sso_id) || opts[:application]&.uid,
      iat: issued_at,
      exp: issued_at + opts[:expires_in].to_i
    }
  end

  secret_key Rails.application.config.x.oauth.signing_key_pem
  signing_method :rs256
end
