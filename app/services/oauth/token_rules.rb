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
  #   - client not approved (pending/revoked)   → invalid_client (RFC 6749 §5.2);
  #   - resource owner disabled                  → invalid_grant;
  #   - code already redeemed (replay)           → invalid_grant, and every token
  #     issued from that code is revoked (RFC 6749 §4.1.2);
  #   - refresh token already rotated (reuse)    → invalid_grant, and every token
  #     the client holds for that user is revoked (OAuth 2.1 §4.3.1);
  #   - refresh token past its absolute lifetime → invalid_grant.
  #
  # Client authentication itself (secret via Basic or body for confidential
  # clients, none for public ones, a public client presenting a secret refused)
  # is Doorkeeper's `by_uid_and_secret`; PKCE and redirect_uri binding are
  # Doorkeeper's `validate_code_verifier` / `validate_redirect_uri`.
  #
  # Every token issued here carries `access_grant_id` — the code it descends
  # from, kept across refresh rotations — which is what "the tokens issued
  # from that code" means above. After a successful response the id_token
  # (openid scope) gets the hub's `at_hash` and the client's `last_used_at`
  # is touched.
  module TokenRules
    private

    # AuthorizationCodeRequest#validate_client / RefreshTokenRequest#validate_client.
    def validate_client
      super && client_usable?
    end

    # AuthorizationCodeRequest: a revoked grant is a replayed code; otherwise
    # the grant's user must still be active.
    def validate_grant
      if grant&.revoked?
        Tokens.revoke_issued_from!(grant)
        return false
      end

      super && resource_owner_active?(grant.resource_owner_id)
    end

    # RefreshTokenRequest: a revoked refresh token is a reused one; otherwise
    # it must be within its lifetime, its own client (public clients send no
    # credentials) usable and its user still active.
    def validate_token
      return false if Tokens.detect_reuse!(refresh_token)

      super && Tokens.refresh_token_alive?(refresh_token) && refresh_token_client_usable? &&
        resource_owner_active?(refresh_token.resource_owner_id)
    end

    # Both requests: the new token joins the family of the code it descends
    # from (Doorkeeper copies these attributes onto the created token).
    def custom_token_attributes_with_data
      super.merge(access_grant_id: family_grant_id)
    end

    # Both requests, after the token is issued.
    def after_successful_response
      super
      if access_token.includes_scope?("openid")
        @response.id_token = IdToken.new(access_token, @response.id_token&.nonce)
      end
      # Registry metadata only; validations and updated_at are deliberately untouched.
      access_token.application&.update_column(:last_used_at, Time.current) # rubocop:disable Rails/SkipsModelValidations
    end

    def family_grant_id
      respond_to?(:grant) ? grant.id : refresh_token.access_grant_id
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
