# Request rate limits (TASK-028): Rails' `rate_limit`, counted in the shared
# cache (Redis, TASK-027). Read and validated at boot — a typo must not
# silently lift a limit. Each value is a positive integer: requests per key and
# window. Behind a reverse proxy the address is the client's only once Rails
# trusts the proxy (config.action_dispatch.trusted_proxies, TASK-033).
#
#   OAUTH_TOKEN_RATE_LIMIT        POST /oauth/token, per client and address, per minute (300)
#   OAUTH_REVOKE_RATE_LIMIT       POST /oauth/revoke, per client and address, per minute (60)
#   OAUTH_INTROSPECT_RATE_LIMIT   POST /oauth/introspect, per client and address, per minute (1200)
#   SIGN_IN_RATE_LIMIT            sign-in attempts per address, per minute (20)
#   SIGN_IN_EMAIL_RATE_LIMIT      sign-in attempts per submitted email, per minute (10)
#   ACCOUNT_MAIL_RATE_LIMIT       password-reset and unlock requests per address, per hour (20)
#   ACCOUNT_MAIL_EMAIL_RATE_LIMIT password-reset and unlock requests per submitted email, per hour (5)
#
# POST /oauth/register keeps OAUTH_REGISTRATION_IP_LIMIT (per address, per
# hour; config/initializers/oauth_registration.rb).
rate_limit_setting = lambda do |name, default|
  value = ENV.fetch(name, default.to_s)
  limit = Integer(value, 10, exception: false)
  raise "#{name} must be a positive integer (requests per window), got #{value.inspect}" unless limit&.positive?

  limit
end

Rails.application.config.x.rate_limits = ActiveSupport::OrderedOptions.new.merge!(
  oauth_token: rate_limit_setting.call("OAUTH_TOKEN_RATE_LIMIT", 300),
  oauth_revoke: rate_limit_setting.call("OAUTH_REVOKE_RATE_LIMIT", 60),
  oauth_introspect: rate_limit_setting.call("OAUTH_INTROSPECT_RATE_LIMIT", 1200),
  sign_in: rate_limit_setting.call("SIGN_IN_RATE_LIMIT", 20),
  sign_in_email: rate_limit_setting.call("SIGN_IN_EMAIL_RATE_LIMIT", 10),
  account_mail: rate_limit_setting.call("ACCOUNT_MAIL_RATE_LIMIT", 20),
  account_mail_email: rate_limit_setting.call("ACCOUNT_MAIL_EMAIL_RATE_LIMIT", 5)
)

# Devise's controllers are reloaded with the app's code in development, so the
# limits are attached on every prepare (doorkeeper.rb does the same for the
# token endpoint).
Rails.application.config.to_prepare do
  Devise::SessionsController.include(AccountRateLimits::SignIn)
  Devise::PasswordsController.include(AccountRateLimits::AccountMail)
  Devise::UnlocksController.include(AccountRateLimits::AccountMail)
end
