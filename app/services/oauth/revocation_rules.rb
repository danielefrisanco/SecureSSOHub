module OAuth
  # The hub's token lookup for POST /oauth/revoke (RFC 7009) and
  # POST /oauth/introspect (RFC 7662), prepended into Doorkeeper::TokensController
  # from config/initializers/doorkeeper.rb. Doorkeeper already authenticates the
  # client, answers 200 for an unknown token and refuses another client's token
  # (403 unauthorized_client, RFC 7009 §2.1); on top of that:
  #
  #   - `token_type_hint` is a hint, not a filter: a token not found under the
  #     hinted type is looked up under the other (RFC 7009 §2.1) — Doorkeeper
  #     stops at refresh tokens when the hint names them;
  #   - revoking a token revokes its family (OAuth::Tokens.revoke_family!), so a
  #     refresh token takes its access tokens with it, and a live refresh token
  #     sharing the row of an already expired access token is revoked too;
  #   - introspection only describes access tokens: a refresh token is never a
  #     credential a resource server may accept, so it is not found and comes
  #     back `active: false`.
  module RevocationRules
    private

    # Doorkeeper::TokensController#revocable_token, shared by #revoke and #introspect.
    def revocable_token
      return @revocable_token if defined?(@revocable_token)

      @revocable_token =
        if action_name == "introspect"
          access_token
        elsif params[:token_type_hint] == "refresh_token"
          refresh_token || access_token
        else
          access_token || refresh_token
        end
    end

    # Runs once the client is known to own the token.
    def revoke_token
      Tokens.revoke_family!(revocable_token.token)
    end
  end
end
