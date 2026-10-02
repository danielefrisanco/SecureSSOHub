require_relative "../../lib/middleware/request_body_limit"

# Dynamic client registration (RFC 7591, POST /oauth/register — TASK-025).
# Read and validated at boot like the other OAuth settings; the app reads
# them through OAuth::RegistrationPolicy.
#
#   OAUTH_REGISTRATION_POLICY    approval (default): registered clients are
#                                pending until an administrator approves them;
#                                open: approved at once, public (PKCE) clients
#                                only; closed: no endpoint (404), not advertised.
#   OAUTH_REGISTRATION_IP_LIMIT  registrations accepted per source address and
#                                hour (default 20) until rate limiting (T24).
registration_policies = %w[approval open closed]
registration_policy = ENV.fetch("OAUTH_REGISTRATION_POLICY", "approval")
unless registration_policies.include?(registration_policy)
  raise "OAUTH_REGISTRATION_POLICY must be one of #{registration_policies.join(', ')}, " \
        "got #{registration_policy.inspect}"
end
Rails.application.config.x.oauth.registration_policy = registration_policy.to_sym
Rails.application.config.x.oauth.registration_ip_limit = Integer(ENV.fetch("OAUTH_REGISTRATION_IP_LIMIT", 20))

# Client metadata is a few hundred bytes; anything near this is not a client.
Rails.application.config.middleware.insert_before 0, RequestBodyLimit, paths: ["/oauth/register"],
                                                                       max_bytes: 16.kilobytes
