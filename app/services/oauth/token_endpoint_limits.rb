module OAuth
  # Rate limits on POST /oauth/token, /oauth/revoke and /oauth/introspect
  # (TASK-028), prepended into Doorkeeper::TokensController from
  # config/initializers/doorkeeper.rb; limits per minute from
  # config/initializers/rate_limits.rb.
  #
  # A request naming an approved client is counted per client *and* address:
  # a server-side client refreshing for many users gets a budget of its own,
  # and nobody who merely knows a public client_id can spend that budget from
  # elsewhere (a per-client_id counter would let anyone lock a client out).
  # Everything else — no client_id, an unknown or unapproved one — is counted
  # per address, so invented client_ids buy no extra requests.
  module TokenEndpointLimits
    LIMITS = { create: :oauth_token, revoke: :oauth_revoke, introspect: :oauth_introspect }.freeze

    def self.prepended(base)
      base.include(EndpointRateLimits)
      limits = Rails.configuration.x.rate_limits
      LIMITS.each do |action, setting|
        base.oauth_rate_limit(action, limit: limits.public_send(setting), within: 1.minute, by: :rate_limit_key)
      end
    end

    private

    def rate_limit_key
      client_id = presented_client_id
      Clients.usable?(client_id) ? "#{client_id}:#{request.remote_ip}" : request.remote_ip
    end

    # Where Doorkeeper looks for it: HTTP Basic first, then the parameter.
    def presented_client_id
      if request.authorization.to_s.start_with?("Basic ")
        ActionController::HttpAuthentication::Basic.user_name_and_password(request).first.to_s
      else
        params[:client_id].to_s
      end
    end
  end
end
