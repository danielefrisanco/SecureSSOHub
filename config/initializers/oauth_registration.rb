require_relative "../../lib/middleware/request_body_limit"

# Dynamic client registration (RFC 7591, POST /oauth/register — TASK-025).
# Read and validated at boot like the other OAuth settings; the app reads
# them through OAuth::RegistrationPolicy.
#
#   OAUTH_REGISTRATION_POLICY    approval (default): registered clients are
#                                pending until an administrator approves them;
#                                open: approved at once, public (PKCE) clients
#                                only; closed: no endpoint (404), not advertised.
#   OAUTH_REGISTRATION_IP_LIMIT  registration attempts per source address and
#                                hour (default 20), a rate limit (TASK-028).
registration_policies = %w[approval open closed]
registration_policy = ENV.fetch("OAUTH_REGISTRATION_POLICY", "approval")
unless registration_policies.include?(registration_policy)
  raise "OAUTH_REGISTRATION_POLICY must be one of #{registration_policies.join(', ')}, " \
        "got #{registration_policy.inspect}"
end
Rails.application.config.x.oauth.registration_policy = registration_policy.to_sym
registration_ip_limit = ENV.fetch("OAUTH_REGISTRATION_IP_LIMIT", "20")
unless Integer(registration_ip_limit, 10, exception: false)&.positive?
  raise "OAUTH_REGISTRATION_IP_LIMIT must be a positive integer (requests per window), " \
        "got #{registration_ip_limit.inspect}"
end
Rails.application.config.x.oauth.registration_ip_limit = Integer(registration_ip_limit, 10)

# Client metadata is a few hundred bytes; anything near this is not a client.
Rails.application.config.middleware.insert_before 0, RequestBodyLimit, paths: ["/oauth/register"],
                                                                       max_bytes: 16.kilobytes
