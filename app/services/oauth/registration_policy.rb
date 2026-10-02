module OAuth
  # Who may register a client through POST /oauth/register (RFC 7591):
  # OAUTH_REGISTRATION_POLICY, validated at boot by
  # config/initializers/oauth_registration.rb.
  #
  #   approval  (default) the client is created pending and cannot authorize
  #             or obtain tokens until an administrator approves it
  #             (OAuth::Clients.approve);
  #   open      the client is approved at once, but only a public (PKCE)
  #             client with user-consentable scopes;
  #   closed    no endpoint (404) and no `registration_endpoint` in discovery.
  module RegistrationPolicy
    module_function

    # @return [Symbol] :approval, :open or :closed
    def current
      Rails.configuration.x.oauth.registration_policy
    end

    # @return [Boolean] whether the endpoint exists and is advertised.
    def enabled?
      current != :closed
    end

    # Registrations accepted per source address and hour (OAUTH_REGISTRATION_IP_LIMIT).
    #
    # @return [Integer]
    def ip_limit
      Rails.configuration.x.oauth.registration_ip_limit
    end
  end
end
