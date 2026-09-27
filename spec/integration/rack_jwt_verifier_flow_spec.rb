require "rails_helper"
require "rack/builder"
require "rack/mock"
require "support/hub_access_token"
require "support/omniauth_client_flow"

# The proof that downstream services can use rack-jwt-verifier as shipped
# against this hub (TASK-020, extended in TASK-023): a standalone Rack app (no
# Rails, no hub code) verifies real hub access tokens — including the one an
# omniauth-ssoprovider login hands its client — from the hub's published JWKS
# document, reads the claims the hub documents (docs/ARCHITECTURE.md §3) and
# keeps working across a signing-key rotation.
RSpec.describe "rack-jwt-verifier against the hub", type: :request do
  include HubAccessToken
  include OmniauthClientFlow

  let(:jwks_url) { "https://hub.test/.well-known/jwks.json" }
  let(:user) { create(:user, name: "Ada Lovelace") }
  let(:client) { create(:oauth_client, :public, scopes: "openid profile email") }
  let(:hub_api) { OAuth::Resources.hub_api }

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

  # The gem fetches the JWKS over HTTPS; WebMock routes it to the in-process hub.
  before { route_hub_over_http }

  # The hub from now on signs with the first key and publishes the rest as
  # previous keys, as after an OIDC_SIGNING_KEY / OIDC_SIGNING_KEY_PREVIOUS change.
  def rotate_signing_key(*pems)
    allow(OAuth::SigningKey).to receive(:for).and_return(OAuth::SigningKey.new(pems))
  end

  def kid(token)
    JWT.decode(token, nil, false).last.fetch("kid")
  end

  describe "with the token of an omniauth-ssoprovider login" do
    it "accepts it for the hub API audience and exposes subject and scopes" do
      login_client = create(:oauth_client, redirect_uri: OmniauthClientFlow::CALLBACK_URL,
                                           scopes: "openid profile email")
      browser = client_browser(omniauth_client_app(login_client))
      auth = JSON.parse(finish_login(browser, authorize_at_hub(start_login(browser), user: user)).body)

      reply = call(service(jwks_url: jwks_url, require_scopes: ["email"]), auth.dig("extra", "access_token"))
      expect(reply.status).to eq(200)
      expect(JSON.parse(reply.body)).to include("sub" => user.sso_id, "aud" => hub_api,
                                                "scopes" => %w[openid profile email])
    end
  end

  describe "across a signing-key rotation" do
    let(:new_key_pem) { OpenSSL::PKey::RSA.new(2048).to_pem }

    it "keeps a running service accepting old tokens and picks up the new key on its first new token" do
      old_key_pem = OAuth::SigningKey.for(realm: :default).private_key.to_pem
      running = service(jwks_url: jwks_url)
      before_rotation = obtain_access_token(user: user, client: client, scope: "openid", resource: hub_api)
      expect(call(running, before_rotation).status).to eq(200)

      rotate_signing_key(new_key_pem, old_key_pem)
      after_rotation = obtain_access_token(user: user, client: client, scope: "openid", resource: hub_api)
      expect(kid(after_rotation)).not_to eq(kid(before_rotation))

      expect(call(running, after_rotation).status).to eq(200) # unknown kid: one refetch of the JWKS
      expect(call(running, before_rotation).status).to eq(200) # the previous key is still published
      expect(a_request(:get, jwks_url)).to have_been_made.twice
    end

    it "refuses tokens of a retired key once it is no longer published" do
      before_rotation = obtain_access_token(user: user, client: client, scope: "openid", resource: hub_api)

      rotate_signing_key(new_key_pem)
      reply = call(service(jwks_url: jwks_url), before_rotation)
      expect(reply.status).to eq(401)
      expect(reply.headers["www-authenticate"]).to start_with('Bearer error="invalid_token"')
    end
  end

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
