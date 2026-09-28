module OAuth
  # Who may call POST /oauth/introspect (RFC 7662 §2.1), prepended into
  # Doorkeeper::OAuth::TokenIntrospection from config/initializers/doorkeeper.rb.
  #
  # Only a client authenticating as itself (client_secret_basic or _post).
  # Doorkeeper would also accept a bearer access token as the caller's
  # credential, which lets any token holder probe its client's other tokens.
  # Missing or failed client authentication is 401 invalid_client (RFC 6749
  # §5.2). Whether an authenticated client may learn anything is
  # OAuth::Introspection.allowed?; when it may not, the answer is `active: false`.
  module IntrospectionRules
    private

    def authorize!
      @error = Doorkeeper::Errors::InvalidClient unless authorized_client
    end
  end
end
