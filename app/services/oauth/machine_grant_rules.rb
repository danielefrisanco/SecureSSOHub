module OAuth
  # The hub's rules for the machine grant — OAuth `client_credentials`
  # (RFC 6749 §4.4): a service with no user behind it gets a token for
  # itself. Prepended into Doorkeeper::OAuth::ClientCredentials::Validator
  # from config/initializers/doorkeeper.rb. Doorkeeper's own checks still
  # run first: client authentication (`invalid_client`), approval
  # (`allow_grant_flow_for_client`, `unauthorized_client`) and requested
  # scopes ⊆ the client's registered scopes (`invalid_scope`). On top:
  #
  #   - only a confidential client (RFC 6749 §4.4): a public client has no
  #     secret, so anyone knowing its client_id could mint its tokens
  #     → unauthorized_client;
  #   - only machine scopes (`machine` flag in config/oauth_scopes.yml), so a
  #     client's machine allow-list is its registered scopes that carry the
  #     flag. Never a user or admin scope (there is no user to consent), and
  #     at least one must be requested — without `scope` Doorkeeper falls
  #     back to the default `openid` → invalid_scope;
  #   - the optional RFC 8707 `resource`, validated as at the authorization
  #     endpoint (OAuth::Resources) → invalid_target. It becomes the token's
  #     `aud` (OAuth::TokenPayload); without it `aud` is the client uid.
  #
  # The token: sub = azp = client uid, no user claims, Doorkeeper's
  # 10 minutes, never a refresh token (RFC 6749 §4.4.3; Doorkeeper issues
  # none for this grant). It is created inside OAuth::Tokens.issue_client_token
  # (Issuance below), the one place machine tokens pass through.
  module MachineGrantRules
    # Registered last: the client is authenticated and its scopes checked by then.
    def self.prepended(base)
      base.validate :resource, error: AuthorizationRules::InvalidTarget
    end

    private

    # The request's client is a Doorkeeper::OAuth::Client wrapper; Doorkeeper's
    # check is false when no client authenticated.
    def validate_client_supports_grant_flow
      super && !@request.client.application.public_client?
    end

    def validate_scopes
      super && machine_scopes_only?
    end

    # Doorkeeper calls `validate_<attribute>`, so this cannot end in `?`.
    def validate_resource # rubocop:disable Naming/PredicateMethod
      resource = @request.parameters[:resource]
      resource.nil? || Resources.known?(resource, client_uid: @request.client.uid)
    end

    def machine_scopes_only?
      scopes = @request.scopes.to_a
      scopes.any? && scopes.all? { |scope| Scopes.machine?(scope) }
    end

    # Prepended into Doorkeeper::OAuth::ClientCredentials::Creator: Doorkeeper
    # still creates the token, inside OAuth::Tokens.issue_client_token.
    module Issuance
      def call(client, scopes, attributes = {})
        Tokens.issue_client_token(application: client.application) { super }
      end
    end
  end
end
