require "rails_helper"
require "support/hub_access_token"

# GET /api/v1/userinfo — the document omniauth-ssoprovider reads — behind
# rack-jwt-verifier (TASK-020): the gem verifies the hub's own tokens with
# in-process keys, the controller adds the revocation and disabled-account
# checks a self-contained JWT cannot carry. /oauth/userinfo (OIDC) is
# covered at the end for the same token.
RSpec.describe "GET /api/v1/userinfo", type: :request do
  include HubAccessToken

  let(:user) { create(:user, name: "Ada Lovelace") }
  let(:client) { create(:oauth_client, :public, scopes: "openid profile email offline_access") }
  let(:hub_api) { OAuth::Resources.hub_api }

  def token_for(as: user, scope: "openid profile email", resource: hub_api)
    obtain_access_token(user: as, client: client, scope: scope, resource: resource)
  end

  def userinfo(token)
    get "/api/v1/userinfo", headers: { "Authorization" => "Bearer #{token}" }
  end

  # A token minted with the hub's private key but with claims of our choosing.
  def forged(key: OAuth::SigningKey.for(realm: :default).private_key, kid: nil, **overrides)
    now = Time.now.to_i
    claims = { iss: "https://hub.test", sub: user.sso_id, aud: hub_api, azp: client.uid, scope: "openid",
               scopes: ["openid"], jti: SecureRandom.uuid, iat: now, nbf: now, exp: now + 600 }.merge(overrides)
    JWT.encode(claims, key, "RS256", kid: kid || OAuth::SigningKey.for(realm: :default).kid, typ: "at+jwt")
  end

  def expect_invalid_token(description = nil)
    expect(response).to have_http_status(:unauthorized)
    expect(response.media_type).to eq("application/json")
    expect(response.parsed_body["error"]).to eq("invalid_token")
    challenge = response.headers["www-authenticate"]
    expect(challenge).to start_with('Bearer error="invalid_token"')
    expect(challenge).to include(description) if description
  end

  describe "with a valid token" do
    it "returns exactly the document omniauth-ssoprovider expects, with every scope" do
      userinfo(token_for)
      expect(response).to have_http_status(:ok)
      expect(response.media_type).to eq("application/json")
      expect(response.parsed_body).to eq(
        "id" => user.sso_id, "sub" => user.sso_id, "name" => "Ada Lovelace", "email" => user.email,
        "email_verified" => false, "roles" => []
      )
    end

    it "omits name without profile and email/email_verified without email" do
      userinfo(token_for(scope: "openid"))
      expect(response.parsed_body).to eq("id" => user.sso_id, "sub" => user.sso_id, "roles" => [])

      userinfo(token_for(scope: "openid email"))
      expect(response.parsed_body.keys).to contain_exactly("id", "sub", "email", "email_verified", "roles")

      userinfo(token_for(scope: "openid profile"))
      expect(response.parsed_body.keys).to contain_exactly("id", "sub", "name", "roles")
    end

    it "lists the admin role for an administrator" do
      admin = create(:user, :admin)
      userinfo(token_for(as: admin, scope: "openid"))
      expect(response.parsed_body).to include("id" => admin.sso_id, "roles" => ["admin"])
    end

    it "sets no session cookie" do
      userinfo(token_for)
      expect(response.headers["set-cookie"]).to be_nil
    end

    it "still verifies a token signed by the previous key after a rotation" do
      token = token_for
      pems = Rails.configuration.x.oauth.signing_key_pems
      begin
        Rails.configuration.x.oauth.signing_key_pems = [OpenSSL::PKey::RSA.new(2048).to_pem, pems.first]
        OAuth::SigningKey.reset!
        userinfo(token)
        expect(response).to have_http_status(:ok)
      ensure
        Rails.configuration.x.oauth.signing_key_pems = pems
        OAuth::SigningKey.reset!
      end
    end
  end

  describe "without a usable token" do
    it "answers 401 with the bare Bearer challenge when no token is sent" do
      get "/api/v1/userinfo"
      expect(response).to have_http_status(:unauthorized)
      expect(response.headers["www-authenticate"]).to eq("Bearer")
      expect(response.parsed_body).to include("error" => "missing_token")
    end

    it "refuses a token minted for another audience (the client itself, the MCP endpoint)" do
      userinfo(token_for(resource: nil))
      expect_invalid_token
      userinfo(token_for(resource: OAuth::Resources.hub_mcp))
      expect_invalid_token
    end

    it "refuses an id_token presented as a bearer" do
      body = obtain_token_response(user: user, client: client, scope: "openid", resource: hub_api)
      userinfo(body.fetch("id_token"))
      expect_invalid_token
    end

    it "refuses a token from another issuer" do
      userinfo(forged(iss: "https://other.test"))
      expect_invalid_token
    end

    it "refuses an expired token" do
      token = token_for
      Timecop.travel(11.minutes.from_now) { userinfo(token) }
      expect_invalid_token
    end

    it "refuses a tampered token" do
      header, payload, signature = token_for.split(".")
      claims = JSON.parse(Base64.urlsafe_decode64(payload))
      tampered = Base64.urlsafe_encode64(JSON.generate(claims.merge("admin" => true)), padding: false)
      userinfo([header, tampered, signature].join("."))
      expect_invalid_token
    end

    it "refuses a token signed by a key the hub does not publish" do
      foreign = OpenSSL::PKey::RSA.new(2048)
      userinfo(forged(key: foreign))
      expect_invalid_token
      userinfo(forged(key: foreign, kid: "other"))
      expect_invalid_token
    end

    it "refuses a revoked token" do
      token = token_for
      OAuth::Tokens.revoke_for(user: user, client_uid: client.uid)
      userinfo(token)
      expect_invalid_token("revoked")
    end

    it "refuses a token whose jti the hub never issued" do
      userinfo(forged)
      expect_invalid_token("revoked")
    end

    it "refuses a disabled user" do
      token = token_for
      user.update!(disabled_at: Time.current)
      userinfo(token)
      expect_invalid_token("disabled")
    end
  end

  describe "the guard's reach" do
    it "leaves everything outside /api alone" do
      get "/oauth/authorize"
      expect(response).not_to have_http_status(:unauthorized)
      get "/.well-known/jwks.json"
      expect(response).to have_http_status(:ok)
      get "/users/sign_in"
      expect(response).to have_http_status(:ok)
    end

    it "covers unknown paths under /api" do
      get "/api/nothing"
      expect(response).to have_http_status(:unauthorized)
      expect(response.headers["www-authenticate"]).to eq("Bearer")
    end

    it "covers the path variants the router normalises to /api" do
      %w[//api/v1/userinfo ///api/v1/userinfo /api/v1/userinfo/].each do |path|
        get path
        expect(response).to have_http_status(:unauthorized), path
        expect(response.headers["www-authenticate"]).to eq("Bearer"), path
      end
    end

    # Devise configures Warden (failure app, intercept_401 off) only once the
    # routes are finalised, which is lazy in test/development: a 401 from the
    # guard on the first request of a process must not pass through Warden.
    it "sits outside Warden so an API 401 never becomes a sign-in flow" do
      stack = Rails.application.middleware.map(&:klass)
      expect(stack.index(RackJwtVerifier::Middleware)).to be < stack.index(Warden::Manager)
    end

    it "still serves a normalised path with a valid token" do
      get "//api/v1/userinfo", headers: { "Authorization" => "Bearer #{token_for}" }
      expect(response).to have_http_status(:ok)
    end
  end

  describe "GET /oauth/userinfo (OIDC) with the same token" do
    it "returns the scope-gated OIDC claims" do
      get "/oauth/userinfo", headers: { "Authorization" => "Bearer #{token_for}" }
      expect(response).to have_http_status(:ok)
      expect(response.parsed_body).to eq("sub" => user.sso_id, "name" => "Ada Lovelace", "email" => user.email,
                                         "email_verified" => false)

      get "/oauth/userinfo", headers: { "Authorization" => "Bearer #{token_for(scope: 'openid')}" }
      expect(response.parsed_body).to eq("sub" => user.sso_id)
    end

    it "refuses a revoked token with 401" do
      token = token_for
      OAuth::Tokens.revoke_for(user: user, client_uid: client.uid)
      get "/oauth/userinfo", headers: { "Authorization" => "Bearer #{token}" }
      expect(response).to have_http_status(:unauthorized)
      expect(response.headers["www-authenticate"]).to include("Bearer")
    end
  end
end
