# Rails' `rate_limit` fixes its limit when the controller class loads, so a
# spec cannot lower it. Instead it spends the configured budget by filling
# the counter Rails keeps in the cache — the key format of
# ActionController::RateLimiting#rate_limiting: if Rails changes it, the
# specs using this fail loudly instead of passing by accident.
module RateLimits
  # @param scope [String] the controller path, e.g. "doorkeeper/tokens"
  # @param name [String] the limit's name
  # @param by [String] the key the limit counts by
  # @param count [Integer] requests to record as already made
  # @param within [ActiveSupport::Duration] the limit's window
  def spend_rate_limit(scope:, name:, by:, count:, within:)
    Rails.cache.increment(["rate-limit", scope, name, by].join(":"), count, expires_in: within)
  end

  def rate_limits
    Rails.configuration.x.rate_limits
  end
end
