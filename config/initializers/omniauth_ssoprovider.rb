# config/initializers/omniauth_ssoprovider.rb

# The 'omniauth-ssoprovider' gem is required via the Gemfile using:
# gem "omniauth-ssoprovider", require: "omniauth/strategies/ssoprovider"

Rails.application.config.middleware.use OmniAuth::Builder do
  # We use blocks or default strings for ENV.fetch to prevent the app from 
  # crashing during Docker build/assets:precompile when these vars aren't set yet.
  provider :ssoprovider,
    ENV.fetch('SSO_CLIENT_ID') { 'development_id' },
    ENV.fetch('SSO_CLIENT_SECRET') { 'development_secret' },
    
    # Client Options - Configures the connection to the SSO Hub
    client_options: {
      # Base URL of the SSO provider (REQUIRED)
      site: ENV.fetch('SSO_HUB_URL') { 'http://localhost:3000' },
      
      # Authorization endpoint path (Default: '/oauth/authorize')
      authorize_url: '/oauth/authorize',
      
      # Token exchange endpoint path (Default: '/oauth/token')
      token_url: '/oauth/token'
    },

    # Strategy Options - Specific to fetching user details
    # Required by the omniauth-ssoprovider gem to fetch user details after token exchange
    user_info_url: '/api/v1/userinfo',
    
    # Optional: Define the OAuth scopes
    scope: 'read_profile read_email'
end

# Ensure OmniAuth failures are handled by the controller instead of raising an exception in development
OmniAuth.config.on_failure = Proc.new do |env|
  OmniAuth::FailureEndpoint.new(env).redirect_to_failure
end