module OAuth
  # The hub's rules for redeeming an authorization code or a refresh token,
  # prepended into Doorkeeper::OAuth::AuthorizationCodeRequest and
  # Doorkeeper::OAuth::RefreshTokenRequest from config/initializers/doorkeeper.rb.
  #
  # `allow_grant_flow_for_client` only guards the authorization endpoint and
  # the client_credentials flow, so without these checks a code (1 minute) or
  # a refresh token issued *before* a client was revoked, or before its user
  # was disabled, could still be exchanged for a fresh access token.
  #
  #   - client not approved (pending/revoked) → invalid_client (RFC 6749 §5.2);
  #   - resource owner disabled                → invalid_grant.
  module TokenRules
    private

    # AuthorizationCodeRequest#validate_client / RefreshTokenRequest#validate_client.
    def validate_client
      super && client_usable?
    end

    # AuthorizationCodeRequest: the grant's user must still be active.
    def validate_grant
      super && resource_owner_active?(grant.resource_owner_id)
    end

    # RefreshTokenRequest: the token's user must still be active, and the
    # token's own client (public clients send no credentials) must be usable.
    def validate_token
      super && refresh_token_client_usable? && resource_owner_active?(refresh_token.resource_owner_id)
    end

    # `client` is a Doorkeeper::OAuth::Client wrapper here, an Application in
    # the refresh flow.
    def client_usable?
      return true if client.nil?

      application = client.respond_to?(:application) ? client.application : client
      application.usable?
    end

    def refresh_token_client_usable?
      refresh_token.application.nil? || refresh_token.application.usable?
    end

    def resource_owner_active?(user_id)
      return true if user_id.nil?

      User.exists?(id: user_id, disabled_at: nil)
    end
  end
end
