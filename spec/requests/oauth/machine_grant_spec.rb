require "rails_helper"
require "base64"
require "support/hub_access_token"

# POST /oauth/token with grant_type=client_credentials — the machine grant
# (RFC 6749 §4.4, TASK-024): a confidential, approved service obtains a token
# for itself, limited to the machine scopes it is registered with.
RSpec.describe "OAuth machine grant", type: :request do
  include HubAccessToken

  let(:service) { create(:oauth_client, :machine) }
  let(:hub_api) { OAuth::Resources.hub_api }

  def basic_auth(client, secret = client.plaintext_secret)
    { "Authorization" => "Basic #{Base64.strict_encode64("#{client.uid}:#{secret}")}" }
  end

  def request_token(client = service, headers: basic_auth(client), **params)
    post "/oauth/token", params: { grant_type: "client_credentials", scope: "introspect" }.merge(params).compact,
                         headers: headers
  end

  # Decodes a token the way a resource server does: against the published JWKS.
  def decode(jwt)
    get "/.well-known/jwks.json"
    JWT.decode(jwt, nil, true, algorithms: ["RS256"], jwks: JWT::JWK::Set.new(response.parsed_body))
  end

  def expect_error(status, code)
    expect(response).to have_http_status(status)
    expect(response.parsed_body["error"]).to eq(code)
    expect(response.parsed_body).not_to have_key("access_token")
  end

  describe "a confidential, approved service" do
    it "gets a 10-minute RS256 JWT about itself, with no user claims and no refresh token" do
      Timecop.freeze do
        request_token
        expect(response).to have_http_status(:ok)
        body = response.parsed_body
        expect(body.keys).to contain_exactly("access_token", "token_type", "expires_in", "scope", "created_at")
        expect(body).to include("token_type" => "Bearer", "expires_in" => 600, "scope" => "introspect")

        claims, header = decode(body.fetch("access_token"))
        expect(header).to include("alg" => "RS256", "typ" => "at+jwt",
                                  "kid" => OAuth::SigningKey.for(realm: :default).kid)
        expect(claims).to eq(
          "iss" => OAuth::Resources.issuer, "sub" => service.uid, "aud" => service.uid, "azp" => service.uid,
          "scope" => "introspect", "scopes" => ["introspect"], "jti" => claims.fetch("jti"),
          "iat" => Time.current.to_i, "nbf" => Time.current.to_i, "exp" => 10.minutes.from_now.to_i
        )
        expect(OAuth::Tokens.active?(jti: claims.fetch("jti"))).to be(true)
      end
    end

    it "may authenticate with client_secret_post as well" do
      request_token(headers: {}, client_id: service.uid, client_secret: service.plaintext_secret)
      expect(response).to have_http_status(:ok)
    end

    it "gets the requested resource as audience" do
      request_token(resource: hub_api)
      expect(response).to have_http_status(:ok)
      expect(decode(response.parsed_body.fetch("access_token")).first).to include("aud" => hub_api,
                                                                                  "azp" => service.uid)
    end

    it "is issued through OAuth::Tokens, which touches the client's last_used_at" do
      allow(OAuth::Tokens).to receive(:issue_client_token).and_call_original
      request_token
      expect(OAuth::Tokens).to have_received(:issue_client_token).once
      expect(service.reload.last_used_at).to be_within(5.seconds).of(Time.current)
    end

    it "keeps its earlier token live when it gets a new one (rollover)" do
      jtis = Array.new(2) do
        request_token
        JWT.decode(response.parsed_body.fetch("access_token"), nil, false).first.fetch("jti")
      end
      expect(jtis.uniq.size).to eq(2)
      expect(jtis.map { |jti| OAuth::Tokens.active?(jti: jti) }).to eq([true, true])
    end
  end

  describe "scopes" do
    it "refuses a machine scope the client is not registered with" do
      request_token(create(:oauth_client, scopes: "openid profile"))
      expect_error(:bad_request, "invalid_scope")
    end

    it "refuses user scopes, even registered ones" do
      client = create(:oauth_client, scopes: "openid profile email offline_access introspect")
      %w[openid profile email offline_access].each do |scope|
        request_token(client, scope: "introspect #{scope}")
        expect_error(:bad_request, "invalid_scope")
      end
    end

    it "refuses admin scopes, even registered ones" do
      request_token(create(:oauth_client, scopes: "introspect admin:clients"), scope: "admin:clients")
      expect_error(:bad_request, "invalid_scope")
    end

    it "refuses a scope outside the catalogue" do
      request_token(scope: "introspect write:everything")
      expect_error(:bad_request, "invalid_scope")
    end

    it "refuses a request without a scope (the default openid is a user scope)" do
      request_token(scope: nil)
      expect_error(:bad_request, "invalid_scope")

      request_token(create(:oauth_client, scopes: "openid introspect"), scope: nil)
      expect_error(:bad_request, "invalid_scope")
    end
  end

  # Doorkeeper answers unauthorized_client with 401 (RFC 6749 §5.2 would say
  # 400); the error code is the contract clients act on.
  describe "clients that may not use the grant" do
    it "refuses a public client" do
      public_client = create(:oauth_client, :public, scopes: "introspect")
      request_token(public_client, headers: {}, client_id: public_client.uid)
      expect_error(:unauthorized, "unauthorized_client")
    end

    it "refuses a pending client" do
      request_token(create(:oauth_client, :machine, :pending))
      expect_error(:unauthorized, "unauthorized_client")
    end

    it "refuses a revoked client" do
      request_token(create(:oauth_client, :machine, :revoked))
      expect_error(:unauthorized, "unauthorized_client")
    end

    it "refuses a wrong secret or no client authentication with invalid_client" do
      request_token(headers: basic_auth(service, "wrong"))
      expect_error(:unauthorized, "invalid_client")

      request_token(headers: {})
      expect_error(:unauthorized, "invalid_client")
    end
  end

  describe "resource indicator" do
    it "refuses an unknown resource with invalid_target" do
      request_token(resource: "https://elsewhere.test/api")
      expect_error(:bad_request, "invalid_target")
    end

    it "refuses a resource with a fragment with invalid_target" do
      request_token(resource: "#{hub_api}#x")
      expect_error(:bad_request, "invalid_target")
    end
  end

  # TASK-024 decision (2026-10-02): introspection stays client-authenticated
  # (TASK-022). The service holding the `introspect` scope calls it as itself;
  # its machine token is described like any other and is no caller credential.
  describe "with the introspect scope" do
    let(:user) { create(:user) }
    let(:machine_token) do
      request_token
      response.parsed_body.fetch("access_token")
    end

    def introspect(token, headers: basic_auth(service))
      post "/oauth/introspect", params: { token: token }, headers: headers
    end

    it "introspects a user's token as itself" do
      app = create(:oauth_client, :public, scopes: "openid")
      user_token = obtain_access_token(user: user, client: app, scope: "openid")

      introspect(user_token)
      expect(response).to have_http_status(:ok)
      expect(response.parsed_body).to include("active" => true, "client_id" => app.uid, "username" => user.sso_id)
    end

    it "sees its machine token as active, with itself as subject and no username" do
      introspect(machine_token)
      expect(response.parsed_body).to include("active" => true, "scope" => "introspect", "client_id" => service.uid,
                                              "sub" => service.uid, "aud" => service.uid)
      expect(response.parsed_body).not_to have_key("username")
    end

    it "cannot use the machine token itself as the caller's credential" do
      introspect(machine_token, headers: { "Authorization" => "Bearer #{machine_token}" })
      expect_error(:unauthorized, "invalid_client")
    end
  end
end
