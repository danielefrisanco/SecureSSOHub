# POST /oauth/register — RFC 7591 dynamic client registration, for clients
# (MCP agents above all) that discover the hub and register themselves.
# Unauthenticated JSON: the rules and the response are
# OAuth::DynamicRegistration, the policy OAuth::RegistrationPolicy (closed →
# 404). Oversized bodies are refused before they reach Rails (RequestBodyLimit,
# config/initializers/oauth_registration.rb).
class ClientRegistrationsController < ApplicationController
  include OAuth::EndpointRateLimits

  skip_forgery_protection
  # The body is read raw by OAuth::DynamicRegistration, never as params.
  wrap_parameters false
  # Every attempt counts, accepted or refused (OAUTH_REGISTRATION_IP_LIMIT).
  oauth_rate_limit :create, limit: OAuth::RegistrationPolicy.ip_limit, within: 1.hour,
                            if: -> { OAuth::RegistrationPolicy.enabled? }

  def create
    return head(:not_found) unless OAuth::RegistrationPolicy.enabled?

    result = OAuth::DynamicRegistration.call(request.raw_post, ip: request.remote_ip)
    # The response may carry the one-time client_secret.
    response.headers["Cache-Control"] = "no-store"
    render json: result.body, status: result.status
  end
end
