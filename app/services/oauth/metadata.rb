module OAuth
  # The authorization-server metadata (RFC 8414) and its OpenID Connect
  # Discovery superset, built once here for both well-known documents
  # (WellKnownController). Every URL is the issuer (HUB_ISSUER) plus the
  # mounted route's path — never the request Host, which a client could spoof.
  #
  # Capabilities are read from the live Doorkeeper configuration and the scope
  # catalogue so the document cannot drift from what the endpoints enforce.
  module Metadata
    module_function

    SERVICE_DOCUMENTATION = "https://github.com/danielefrisanco/SecureSSOHub#readme".freeze

    # Claims an id_token / access token / userinfo response may carry
    # (OAuth::TokenPayload, OAuth::IdToken and the claims block of the OIDC
    # initializer), standard ones first.
    CLAIMS_SUPPORTED = %w[sub iss aud exp iat auth_time nonce name email email_verified admin].freeze

    # Doorkeeper's names for the ways a confidential client may present its
    # secret at the token endpoint → RFC 8414 names.
    CLIENT_SECRET_METHODS = { from_basic: "client_secret_basic", from_params: "client_secret_post" }.freeze

    # @param oidc [Boolean] true for openid-configuration (adds the OIDC-only
    #   fields), false for oauth-authorization-server
    # @return [Hash{String => Object}] the document, ready to render as JSON
    def document(oidc:)
      base = {
        "issuer" => issuer,
        "authorization_endpoint" => url(routes.oauth_authorization_path),
        "token_endpoint" => url(routes.oauth_token_path),
        "revocation_endpoint" => url(routes.oauth_revoke_path),
        "introspection_endpoint" => url(routes.oauth_introspect_path),
        "jwks_uri" => url(routes.jwks_path),
        "scopes_supported" => OAuth::Scopes.names,
        "response_types_supported" => doorkeeper.authorization_response_types,
        "grant_types_supported" => grant_types_supported,
        "code_challenge_methods_supported" => doorkeeper.pkce_code_challenge_methods,
        "token_endpoint_auth_methods_supported" => token_endpoint_auth_methods_supported,
        "service_documentation" => SERVICE_DOCUMENTATION
      }
      base["registration_endpoint"] = url(routes.oauth_registration_path) if OAuth::RegistrationPolicy.enabled?
      oidc ? base.merge(openid_fields) : base
    end

    def openid_fields
      {
        "userinfo_endpoint" => url(routes.oauth_userinfo_path),
        "id_token_signing_alg_values_supported" => [Doorkeeper::OpenidConnect.signing_algorithm.to_s],
        "subject_types_supported" => Doorkeeper::OpenidConnect.configuration.subject_types_supported.map(&:to_s),
        "claims_supported" => CLAIMS_SUPPORTED
      }
    end

    # Refresh tokens are not a Doorkeeper grant flow but are issued
    # (use_refresh_token in the initializer), so they are advertised alongside.
    def grant_types_supported
      doorkeeper.grant_flows + ["refresh_token"]
    end

    # `none` is for public clients, whose code exchange is PKCE-bound instead.
    def token_endpoint_auth_methods_supported
      doorkeeper.client_credentials_methods.filter_map { |method| CLIENT_SECRET_METHODS[method] } + ["none"]
    end

    def issuer
      OAuth::Resources.issuer
    end

    def url(path)
      "#{issuer.chomp('/')}#{path}"
    end

    def routes
      Rails.application.routes.url_helpers
    end

    def doorkeeper
      Doorkeeper.configuration
    end
  end
end
