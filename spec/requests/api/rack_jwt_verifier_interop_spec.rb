require "rails_helper"
require "rack/builder"
require "rack/mock"
require "support/hub_access_token"

# The proof that downstream services can use rack-jwt-verifier as shipped
# against this hub: a standalone Rack app (no Rails, no hub code) verifies a
# real hub access token from the hub's published JWKS document and reads the
# claims the hub documents (docs/ARCHITECTURE.md §3).
RSpec.describe "rack-jwt-verifier interop", type: :request do
  include HubAccessToken

  let(:jwks_url) { "https://hub.test/.well-known/jwks.json" }
  let(:user) { create(:user, name: "Ada Lovelace") }
  let(:client) { create(:oauth_client, :public, scopes: "openid profile email") }
  let(:hub_api) { OAuth::Resources.hub_api }
  # The gem fetches the JWKS over HTTPS; WebMock routes that to the in-process
  # hub, whole stack included. WebMock seeds `rack.session` with a plain Hash
  # that rack-session 2 cannot commit; the hub's public documents need none.
  let(:hub_over_http) do
    ->(env) { Rails.application.call(env.except("rack.session", "rack.session.options")) }
  end

  # A downstream service: the gem in front of an app that echoes the verified payload.
  def service(**options)
    verifier_options = { decode_options: { iss: "https://hub.test", aud: hub_api }, require_token: true,
                         json_errors: true }.merge(options)
    Rack::Builder.new do
      use RackJwtVerifier::Middleware, verifier_options
      run ->(env) { [200, { "content-type" => "application/json" }, [JSON.generate(env["rack_jwt_verifier.payload"])]] }
    end.to_app
  end

  def call(app, token)
    Rack::MockRequest.new(app).get("/whoami", "HTTP_AUTHORIZATION" => "Bearer #{token}")
  end

  before { stub_request(:get, jwks_url).to_rack(hub_over_http) }

  describe "in JWKS mode" do
    it "accepts a hub access token fetched from the hub's JWKS and exposes the claims" do
      token = obtain_access_token(user: user, client: client, scope: "openid profile email", resource: hub_api)
      reply = call(service(jwks_url: jwks_url), token)

      expect(reply.status).to eq(200)
      expect(a_request(:get, jwks_url)).to have_been_made.once
      expect(JSON.parse(reply.body)).to include(
        "iss" => "https://hub.test", "sub" => user.sso_id, "aud" => hub_api, "azp" => client.uid,
        "scopes" => %w[openid profile email], "name" => "Ada Lovelace", "email" => user.email, "admin" => false
      )
    end

    it "refuses a token minted for another audience" do
      token = obtain_access_token(user: user, client: client, scope: "openid", resource: nil)
      reply = call(service(jwks_url: jwks_url), token)
      expect(reply.status).to eq(401)
      expect(reply.headers["www-authenticate"]).to start_with('Bearer error="invalid_token"')
    end

    it "enforces required scopes from the token's scopes claim" do
      token = obtain_access_token(user: user, client: client, scope: "openid", resource: hub_api)
      reply = call(service(jwks_url: jwks_url, require_scopes: ["profile"]), token)
      expect(reply.status).to eq(403)
      expect(reply.headers["www-authenticate"]).to include('error="insufficient_scope"', 'scope="profile"')
    end
  end

  describe "in public_key mode" do
    it "accepts a hub access token with the active key alone, without any fetch" do
      token = obtain_access_token(user: user, client: client, scope: "openid", resource: hub_api)
      reply = call(service(public_key: OAuth::SigningKey.for(realm: :default).public_key), token)
      expect(reply.status).to eq(200)
      expect(JSON.parse(reply.body)).to include("sub" => user.sso_id, "scopes" => ["openid"])
      expect(a_request(:get, jwks_url)).not_to have_been_made
    end
  end
end
