require "rails_helper"
require "base64"
require "support/hub_access_token"

# POST /oauth/introspect — RFC 7662 (TASK-022): only a confidential client
# registered with the `introspect` scope learns anything; the answer for an
# active access token carries exactly the listed fields, anything else is
# `{"active": false}` and nothing more.
RSpec.describe "OAuth token introspection", type: :request do
  include HubAccessToken

  let(:user) { create(:user) }
  let(:scope) { "openid profile offline_access" }
  let(:client) { create(:oauth_client, :public, scopes: scope) }
  let(:resource_server) { create(:oauth_client, name: "Notes API", scopes: "introspect") }
  let(:hub_api) { OAuth::Resources.hub_api }

  def basic_auth(client, secret = client.plaintext_secret)
    { "Authorization" => "Basic #{Base64.strict_encode64("#{client.uid}:#{secret}")}" }
  end

  def introspect(token, headers: basic_auth(resource_server), params: {})
    post "/oauth/introspect", params: { token: token }.merge(params), headers: headers
  end

  def expect_inactive
    expect(response).to have_http_status(:ok)
    expect(response.parsed_body).to eq("active" => false)
  end

  describe "an authorised resource server" do
    it "gets exactly the RFC 7662 fields for an active user token" do
      access_token = obtain_access_token(user: user, client: client, scope: scope, resource: hub_api)
      claims = JWT.decode(access_token, nil, false).first

      introspect(access_token)
      expect(response).to have_http_status(:ok)
      expect(response.parsed_body).to eq(
        "active" => true, "scope" => scope, "client_id" => client.uid, "username" => user.sso_id,
        "token_type" => "Bearer", "exp" => claims.fetch("exp"), "iat" => claims.fetch("iat"),
        "sub" => user.sso_id, "aud" => hub_api, "iss" => OAuth::Resources.issuer, "jti" => claims.fetch("jti")
      )
    end

    it "gets no username for a client_credentials token, whose subject is the client" do
      service = create(:oauth_client, scopes: "introspect")
      post "/oauth/token", params: { grant_type: "client_credentials", scope: "introspect" },
                           headers: basic_auth(service)
      access_token = response.parsed_body.fetch("access_token")

      introspect(access_token)
      expect(response.parsed_body).to include("active" => true, "sub" => service.uid, "aud" => service.uid,
                                              "client_id" => service.uid)
      expect(response.parsed_body).not_to have_key("username")
    end

    it "gets only active: false for a revoked, expired or unknown token" do
      revoked = obtain_access_token(user: user, client: client, scope: scope)
      OAuth::Tokens.revoke(revoked, by: user)
      introspect(revoked)
      expect_inactive

      expired = obtain_access_token(user: user, client: client, scope: scope)
      Timecop.travel(11.minutes.from_now) { introspect(expired) }
      expect_inactive

      introspect("not-a-token")
      expect_inactive
    end

    it "gets only active: false for a refresh token, which is no credential for a resource server" do
      refresh_token = obtain_token_response(user: user, client: client, scope: scope).fetch("refresh_token")

      introspect(refresh_token, params: { token_type_hint: "refresh_token" })
      expect_inactive
    end
  end

  describe "a caller without the right" do
    let(:access_token) { obtain_access_token(user: user, client: client, scope: scope) }

    it "gets only active: false as a confidential client without the introspect scope" do
      introspect(access_token, headers: basic_auth(create(:oauth_client, scopes: "openid")))
      expect_inactive
    end

    it "gets only active: false as a public client, even the token's own" do
      introspect(access_token, headers: {}, params: { client_id: client.uid })
      expect_inactive
    end

    it "gets only active: false as a revoked client that holds the scope" do
      revoked = create(:oauth_client, :revoked, scopes: "introspect")
      introspect(access_token, headers: basic_auth(revoked))
      expect_inactive
    end
  end

  describe "an unauthenticated caller" do
    let(:access_token) { obtain_access_token(user: user, client: client, scope: scope) }

    def expect_invalid_client
      expect(response).to have_http_status(:unauthorized)
      expect(response.parsed_body["error"]).to eq("invalid_client")
      expect(response.parsed_body).not_to have_key("active")
    end

    it "is refused with 401 without any credentials" do
      introspect(access_token, headers: {})
      expect_invalid_client
    end

    it "is refused with 401 with a wrong secret" do
      introspect(access_token, headers: basic_auth(resource_server, "wrong"))
      expect_invalid_client
    end

    it "is refused with 401 when presenting a bearer token instead of client credentials" do
      other = obtain_access_token(user: user, client: client, scope: scope)
      introspect(access_token, headers: { "Authorization" => "Bearer #{other}" })
      expect_invalid_client
    end
  end
end
