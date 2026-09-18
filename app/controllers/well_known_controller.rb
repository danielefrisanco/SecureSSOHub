# Public, unauthenticated documents every client and resource server fetches.
# Served by the hub itself (not the OIDC engine) so the responses carry cache
# headers, the JWKS lists the previous key during a rotation and the
# discovery documents are built from HUB_ISSUER (OAuth::Metadata) rather
# than the request Host.
class WellKnownController < ApplicationController
  skip_forgery_protection

  MAX_AGE = 5.minutes

  # GET /.well-known/jwks.json and GET /oauth/discovery/keys
  def jwks
    render_cached OAuth::SigningKey.for(realm: :default).jwks
  end

  # GET /.well-known/openid-configuration (OpenID Connect Discovery)
  def openid_configuration
    render_cached OAuth::Metadata.document(oidc: true)
  end

  # GET /.well-known/oauth-authorization-server (RFC 8414)
  def oauth_authorization_server
    render_cached OAuth::Metadata.document(oidc: false)
  end

  private

  # Public for five minutes, with an ETag over the body so a revalidation
  # costs a 304.
  def render_cached(document)
    expires_in MAX_AGE, public: true
    return unless stale?(etag: document.to_json)

    render json: document
  end
end
