module Api
  # Base of the hub's bearer-token API (`/api/**`). By the time a request gets
  # here rack-jwt-verifier (config/initializers/rack_jwt_verifier.rb) has
  # checked the signature, `iss`, `aud`, `exp` and `nbf` of the access token
  # and left its claims in the Rack env; what a self-contained JWT cannot tell
  # is checked here, per request: the token was not revoked and, when it
  # belongs to a user, the account is still enabled. Both refusals are 401
  # invalid_token with the RFC 6750 challenge, like the middleware's own.
  #
  # API-only: no session, no cookies, no CSRF — the token alone identifies the caller.
  class BaseController < ActionController::API
    before_action :require_live_token

    private

    # @return [Hash] the verified claims (string keys)
    def token_claims
      request.env.fetch(RackJwtVerifier::Middleware::RACK_ENV_PAYLOAD_KEY)
    end

    # @return [Array<String>] the token's scopes
    def token_scopes
      Array(token_claims["scopes"]).map(&:to_s)
    end

    # The user the token was issued to (`sub` is the sso_id); nil for a
    # client-only token or an unknown subject.
    #
    # @return [User, nil]
    def current_user
      return @current_user if defined?(@current_user)

      @current_user = User.find_by(sso_id: token_claims["sub"])
    end

    def require_live_token
      return invalid_token("the token has been revoked") unless OAuth::Tokens.active?(jti: token_claims["jti"])

      invalid_token("the account is disabled") if current_user&.disabled_at.present?
    end

    # The endpoint is about a user: a client-only token is not enough.
    def require_user
      invalid_token("the token has no user subject") unless current_user
    end

    # RFC 6750 §3.1: 401 with the challenge, body in the shape rack-jwt-verifier uses.
    def invalid_token(description)
      response.set_header("WWW-Authenticate", %(Bearer error="invalid_token", error_description="#{description}"))
      render json: { error: "invalid_token", error_description: description }, status: :unauthorized
    end
  end
end
