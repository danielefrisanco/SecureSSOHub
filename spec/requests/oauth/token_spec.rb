require "rails_helper"
require "base64"
require "digest"

# POST /oauth/token — the HTTP contract of the token endpoint (TASK-019):
# access-token claims, client authentication, PKCE/redirect_uri/code binding,
# single-use codes, refresh rotation and reuse detection, id_token claims, and
# what happens to a code or refresh token issued before the client was revoked
# or the user disabled (TASK-017).
RSpec.describe "OAuth token endpoint", type: :request do
  let(:user) { create(:user, name: "Ada Lovelace") }
  let(:admin) { create(:user, :admin) }
  let(:redirect_uri) { "https://client.test/callback" }
  let(:all_scopes) { "openid profile email offline_access" }
  let(:client) { create(:oauth_client, :public, redirect_uri: redirect_uri, scopes: all_scopes) }
  let(:confidential_client) { create(:oauth_client, redirect_uri: redirect_uri, scopes: all_scopes) }
  let(:verifier) { "b" * 43 }
  let(:challenge) { Base64.urlsafe_encode64(Digest::SHA256.digest(verifier), padding: false) }

  def issue_code(for_client: client, scope: "openid offline_access", as: user, **extra)
    sign_in as
    post "/oauth/authorize", params: { client_id: for_client.uid, redirect_uri: redirect_uri, response_type: "code",
                                       scope: scope, code_challenge: challenge, code_challenge_method: "S256",
                                       **extra }
    sign_out as
    Rack::Utils.parse_query(URI.parse(response.location).query).fetch("code")
  end

  def redeem(code, for_client: client, headers: {}, **overrides)
    params = { grant_type: "authorization_code", client_id: for_client.uid, code: code, redirect_uri: redirect_uri,
               code_verifier: verifier }.merge(overrides).compact
    post "/oauth/token", params: params, headers: headers
  end

  def refresh(token, for_client: client, **overrides)
    post "/oauth/token", params: { grant_type: "refresh_token", client_id: for_client.uid,
                                   refresh_token: token }.merge(overrides)
  end

  def basic_auth(uid, password)
    { "Authorization" => "Basic #{Base64.strict_encode64("#{uid}:#{password}")}" }
  end

  # Decodes a token the way a resource server does: against the published JWKS.
  def decode(jwt)
    get "/.well-known/jwks.json"
    jwks = JWT::JWK::Set.new(response.parsed_body)
    JWT.decode(jwt, nil, true, algorithms: ["RS256"], jwks: jwks)
  end

  def expect_error(status, code)
    expect(response).to have_http_status(status)
    expect(response.parsed_body["error"]).to eq(code)
  end

  describe "authorization-code exchange" do
    it "issues a Bearer JWT to a public client authenticated by PKCE alone" do
      redeem(issue_code)
      expect(response).to have_http_status(:ok)
      expect(response.headers["cache-control"]).to include("no-store")
      body = response.parsed_body
      expect(body).to include("token_type" => "Bearer", "expires_in" => 600, "scope" => "openid offline_access")
      expect(body["access_token"].split(".").length).to eq(3)
    end

    it "issues a token to a confidential client with client_secret_basic" do
      code = issue_code(for_client: confidential_client)
      redeem(code, for_client: confidential_client,
                   headers: basic_auth(confidential_client.uid, confidential_client.plaintext_secret))
      expect(response).to have_http_status(:ok)
      expect(decode(response.parsed_body["access_token"]).first).to include("azp" => confidential_client.uid)
    end

    it "issues a token to a confidential client with client_secret_post" do
      code = issue_code(for_client: confidential_client)
      redeem(code, for_client: confidential_client, client_secret: confidential_client.plaintext_secret)
      expect(response).to have_http_status(:ok)
    end

    it "touches the client's last_used_at" do
      expect(client.last_used_at).to be_nil
      redeem(issue_code)
      expect(client.reload.last_used_at).to be_within(5.seconds).of(Time.current)
    end
  end

  describe "the access token" do
    it "is an RS256 JWT (kid, typ at+jwt) that verifies against the JWKS" do
      redeem(issue_code)
      _payload, header = decode(response.parsed_body["access_token"])
      expect(header).to eq("alg" => "RS256", "kid" => OAuth::SigningKey.for(realm: :default).kid, "typ" => "at+jwt")
    end

    it "carries exactly the documented claims when every scope is granted" do
      redeem(issue_code(scope: all_scopes))
      payload, = decode(response.parsed_body["access_token"])
      expect(payload.keys).to contain_exactly("iss", "sub", "aud", "azp", "scope", "scopes", "jti", "iat", "nbf",
                                              "exp", "name", "email", "email_verified", "admin")
      expect(payload).to include(
        "iss" => "https://hub.test", "sub" => user.sso_id, "aud" => client.uid, "azp" => client.uid,
        "scope" => all_scopes, "scopes" => all_scopes.split, "name" => "Ada Lovelace", "email" => user.email,
        "email_verified" => false, "admin" => false
      )
      expect(payload["jti"]).to match(/\A\h{8}-\h{4}-\h{4}-\h{4}-\h{12}\z/)
      expect(payload["iat"]).to be_within(5).of(Time.now.to_i)
      expect(payload["nbf"]).to eq(payload["iat"])
      expect(payload["exp"]).to eq(payload["iat"] + 600)
    end

    it "omits name and email without the profile and email scopes" do
      redeem(issue_code(scope: "openid offline_access"))
      payload, = decode(response.parsed_body["access_token"])
      expect(payload.keys).to contain_exactly("iss", "sub", "aud", "azp", "scope", "scopes", "jti", "iat", "nbf",
                                              "exp", "admin")
    end

    it "marks an administrator" do
      redeem(issue_code(as: admin))
      payload, = decode(response.parsed_body["access_token"])
      expect(payload).to include("sub" => admin.sso_id, "admin" => true)
    end

    it "takes aud from the resource indicator of the authorization request" do
      redeem(issue_code(resource: OAuth::Resources.hub_mcp))
      payload, = decode(response.parsed_body["access_token"])
      expect(payload).to include("aud" => "https://hub.test/mcp", "azp" => client.uid)
    end

    it "gives every token its own jti, even within the same second" do
      Timecop.freeze do
        redeem(issue_code)
        first, = decode(response.parsed_body["access_token"])
        redeem(issue_code)
        second, = decode(response.parsed_body["access_token"])
        expect(second["jti"]).not_to eq(first["jti"])
        expect(second.except("jti")).to eq(first.except("jti"))
      end
    end
  end

  describe "refresh tokens" do
    it "are issued only when offline_access is granted" do
      redeem(issue_code(scope: "openid profile"))
      expect(response).to have_http_status(:ok)
      expect(response.parsed_body).not_to have_key("refresh_token")

      redeem(issue_code(scope: "openid offline_access"))
      expect(response.parsed_body["refresh_token"]).to be_present
    end

    it "rotate on use: a new pair is issued and the used token stops working" do
      redeem(issue_code)
      first = response.parsed_body

      refresh(first["refresh_token"])
      expect(response).to have_http_status(:ok)
      second = response.parsed_body
      expect(second["access_token"]).not_to eq(first["access_token"])
      expect(second["refresh_token"]).to be_present
      expect(second["refresh_token"]).not_to eq(first["refresh_token"])
      expect(second).to include("scope" => "openid offline_access", "expires_in" => 600)
      expect(decode(second["access_token"]).first).to include("sub" => user.sso_id, "aud" => client.uid)
      expect(client.reload.last_used_at).to be_within(5.seconds).of(Time.current)

      refresh(first["refresh_token"])
      expect_error(:bad_request, "invalid_grant")
    end

    it "reuse of a rotated token revokes the whole family for the user and client" do
      redeem(issue_code)
      first = response.parsed_body
      refresh(first["refresh_token"])
      second = response.parsed_body
      other_client = create(:oauth_client, :public, redirect_uri: redirect_uri, scopes: all_scopes)
      redeem(issue_code(for_client: other_client), for_client: other_client)
      elsewhere = response.parsed_body

      refresh(first["refresh_token"])
      expect_error(:bad_request, "invalid_grant")

      refresh(second["refresh_token"])
      expect_error(:bad_request, "invalid_grant")
      expect(OAuth::Tokens.active_for(user: user).map(&:client_uid)).to eq([other_client.uid])

      refresh(elsewhere["refresh_token"], for_client: other_client)
      expect(response).to have_http_status(:ok)
    end

    it "keep the resource (aud) of the original grant" do
      redeem(issue_code(resource: OAuth::Resources.hub_api))
      refresh(response.parsed_body["refresh_token"])
      expect(decode(response.parsed_body["access_token"]).first).to include("aud" => "https://hub.test/api")
    end

    it "expire 30 days after the code was issued, whatever the number of rotations" do
      expect(OAuth::Tokens.refresh_token_ttl).to eq(30.days)
      redeem(issue_code)
      token = response.parsed_body["refresh_token"]

      Timecop.travel(29.days.from_now) do
        refresh(token)
        expect(response).to have_http_status(:ok)
        token = response.parsed_body["refresh_token"]
      end
      Timecop.travel(30.days.from_now + 1.minute) do
        refresh(token)
        expect_error(:bad_request, "invalid_grant")
      end
    end

    it "require the refresh token to belong to the client" do
      redeem(issue_code)
      refresh(response.parsed_body["refresh_token"], for_client: confidential_client,
                                                     client_secret: confidential_client.plaintext_secret)
      expect_error(:bad_request, "invalid_grant")
    end
  end

  describe "the id_token" do
    it "is issued with the openid scope, carries nonce, auth_time and at_hash and verifies with the JWKS" do
      redeem(issue_code(nonce: "n-0S6_WzA2Mj"))
      body = response.parsed_body
      claims, header = decode(body.fetch("id_token"))
      expect(header).to include("alg" => "RS256", "kid" => OAuth::SigningKey.for(realm: :default).kid)
      expect(claims.keys).to contain_exactly("iss", "sub", "aud", "exp", "iat", "nonce", "auth_time", "at_hash")
      expect(claims).to include("iss" => "https://hub.test", "sub" => user.sso_id, "aud" => client.uid,
                                "nonce" => "n-0S6_WzA2Mj", "auth_time" => user.reload.current_sign_in_at.to_i)
      digest = Digest::SHA256.digest(body["access_token"])
      expect(claims["at_hash"]).to eq(Base64.urlsafe_encode64(digest[0, 16], padding: false))
    end

    it "carries name and email only with the profile and email scopes" do
      redeem(issue_code(scope: all_scopes))
      claims, = decode(response.parsed_body["id_token"])
      expect(claims).to include("name" => "Ada Lovelace", "email" => user.email, "email_verified" => false)

      redeem(issue_code(scope: "openid"))
      claims, = decode(response.parsed_body["id_token"])
      expect(claims.keys).not_to include("name", "email", "email_verified")
    end

    it "is not issued without the openid scope" do
      redeem(issue_code(scope: "profile"))
      expect(response).to have_http_status(:ok)
      expect(response.parsed_body).not_to have_key("id_token")
    end

    it "is renewed on refresh, bound to the new access token" do
      redeem(issue_code)
      refresh(response.parsed_body["refresh_token"])
      body = response.parsed_body
      claims, = decode(body.fetch("id_token"))
      expect(claims).to include("sub" => user.sso_id, "aud" => client.uid)
      expect(claims).not_to have_key("nonce")
      digest = Digest::SHA256.digest(body["access_token"])
      expect(claims["at_hash"]).to eq(Base64.urlsafe_encode64(digest[0, 16], padding: false))
    end
  end

  describe "a rejected exchange" do
    it "refuses a wrong code_verifier with invalid_grant" do
      redeem(issue_code, code_verifier: "c" * 43)
      expect_error(:bad_request, "invalid_grant")
    end

    it "refuses a code without code_verifier with invalid_request" do
      redeem(issue_code, code_verifier: nil)
      expect_error(:bad_request, "invalid_request")
    end

    it "refuses an expired code with invalid_grant" do
      code = issue_code
      Timecop.travel(2.minutes.from_now) { redeem(code) }
      expect_error(:bad_request, "invalid_grant")
    end

    it "refuses a replayed code with invalid_grant and revokes the tokens it issued" do
      code = issue_code
      redeem(code)
      first = response.parsed_body
      refresh(first["refresh_token"])
      expect(response).to have_http_status(:ok)
      expect(OAuth::Tokens.active_for(user: user).length).to eq(1)

      redeem(code)
      expect_error(:bad_request, "invalid_grant")
      expect(OAuth::Tokens.active_for(user: user)).to be_empty
    end

    it "refuses a redirect_uri other than the one the code was issued for" do
      redeem(issue_code, redirect_uri: "https://client.test/other")
      expect_error(:bad_request, "invalid_grant")
    end

    it "refuses a code issued to another client" do
      code = issue_code(for_client: confidential_client)
      redeem(code)
      expect_error(:bad_request, "invalid_grant")
    end
  end

  describe "client authentication" do
    it "refuses a wrong secret with invalid_client" do
      code = issue_code(for_client: confidential_client)
      redeem(code, for_client: confidential_client, headers: basic_auth(confidential_client.uid, "wrong"))
      expect_error(:unauthorized, "invalid_client")
      expect(response.headers["www-authenticate"]).to be_present
    end

    it "refuses a confidential client that sends no secret" do
      code = issue_code(for_client: confidential_client)
      redeem(code, for_client: confidential_client)
      expect_error(:unauthorized, "invalid_client")
    end

    it "refuses a public client that presents a secret" do
      redeem(issue_code, client_secret: "anything")
      expect_error(:unauthorized, "invalid_client")
    end

    it "refuses an unknown client" do
      redeem(issue_code, client_id: "nope")
      expect_error(:unauthorized, "invalid_client")
    end

    it "refuses a client that is no longer approved" do
      code = issue_code
      client.update_columns(approval_state: "pending") # rubocop:disable Rails/SkipsModelValidations -- approved→pending is not a legal transition
      redeem(code)
      expect_error(:unauthorized, "invalid_client")
    end
  end

  describe "a code issued before the change" do
    let!(:code) { issue_code }

    it "is refused with invalid_client once the client is revoked" do
      OAuth::Clients.revoke(client.uid, by: admin)
      redeem(code)
      expect_error(:unauthorized, "invalid_client")
    end

    it "is refused with invalid_grant once the user is disabled" do
      user.update!(disabled_at: Time.current)
      redeem(code)
      expect_error(:bad_request, "invalid_grant")
      expect(OAuth::Tokens.active_for(user: user)).to be_empty
    end
  end

  describe "a refresh token issued before the change" do
    let!(:refresh_token) do
      redeem(issue_code)
      response.parsed_body.fetch("refresh_token")
    end

    it "is refused once the client is revoked" do
      OAuth::Clients.revoke(client.uid, by: admin)
      refresh(refresh_token)
      expect_error(:bad_request, "invalid_grant")
    end

    it "is refused once the user is disabled" do
      user.update!(disabled_at: Time.current)
      refresh(refresh_token)
      expect_error(:bad_request, "invalid_grant")
    end
  end
end
