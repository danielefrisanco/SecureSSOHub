module OAuth
  # What POST /oauth/introspect (RFC 7662) tells whom; wired into Doorkeeper's
  # `allow_token_introspection` and `custom_introspection_response` in
  # config/initializers/doorkeeper.rb. Who may call the endpoint at all is
  # OAuth::IntrospectionRules; which token it looks up is OAuth::RevocationRules.
  module Introspection
    # A machine scope (config/oauth_scopes.yml): held by resource servers,
    # never granted to a dynamically registered client.
    SCOPE = "introspect".freeze

    module_function

    # Whether an authenticated client may learn about tokens: it must be
    # confidential, approved and registered with the `introspect` scope. Any
    # other client gets `active: false` for every token.
    #
    # @param client [Doorkeeper::Application, nil]
    # @return [Boolean]
    def allowed?(client)
      return false unless client

      !client.public_client? && client.usable? && client.scopes.to_a.include?(SCOPE)
    end

    # The fields an active token's introspection adds to Doorkeeper's
    # `active`, `scope`, `client_id`, `token_type`, `iat` and `exp`: the
    # `sub`, `aud`, `iss` and `jti` the JWT itself carries (OAuth::TokenPayload)
    # and `username`, the user's sso_id (absent for client_credentials tokens).
    #
    # @param token [Doorkeeper::AccessToken] an active access token
    # @return [Hash]
    def response_fields(token)
      claims = TokenPayload.build(resource_owner_id: token.resource_owner_id, application: token.application,
                                  scopes: token.scopes, expires_in: token.expires_in, created_at: token.created_at,
                                  resource: token.resource, jti: token.jti)
      username = token.resource_owner_id && User.where(id: token.resource_owner_id).pick(:sso_id)
      claims.slice(:sub, :aud, :iss, :jti).merge(username: username).compact
    end
  end
end
