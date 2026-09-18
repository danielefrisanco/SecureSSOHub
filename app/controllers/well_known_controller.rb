# Public, unauthenticated documents every client and resource server fetches.
# Served by the hub itself (not the OIDC engine) so the response carries cache
# headers and lists the previous key during a rotation.
class WellKnownController < ApplicationController
  skip_forgery_protection

  JWKS_MAX_AGE = 5.minutes

  # GET /.well-known/jwks.json and GET /oauth/discovery/keys
  def jwks
    document = OAuth::SigningKey.for(realm: :default).jwks
    expires_in JWKS_MAX_AGE, public: true
    return unless stale?(etag: document.to_json)

    render json: document
  end
end
