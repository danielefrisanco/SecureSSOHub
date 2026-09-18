require "rails_helper"
require "base64"
require "digest"

# POST /oauth/token — what happens to a code or refresh token issued before
# the client was revoked or the user disabled (TASK-017). The full token
# endpoint contract (claims, client authentication) is TASK-019/020.
RSpec.describe "OAuth token endpoint", type: :request do
  let(:user) { create(:user) }
  let(:admin) { create(:user, :admin) }
  let(:redirect_uri) { "https://client.test/callback" }
  let(:client) { create(:oauth_client, :public, redirect_uri: redirect_uri, scopes: "openid offline_access") }
  let(:verifier) { "b" * 43 }
  let(:challenge) { Base64.urlsafe_encode64(Digest::SHA256.digest(verifier), padding: false) }

  def issue_code
    sign_in user
    post "/oauth/authorize", params: { client_id: client.uid, redirect_uri: redirect_uri, response_type: "code",
                                       scope: "openid offline_access", code_challenge: challenge,
                                       code_challenge_method: "S256" }
    sign_out user
    Rack::Utils.parse_query(URI.parse(response.location).query).fetch("code")
  end

  def redeem(code)
    post "/oauth/token", params: { grant_type: "authorization_code", client_id: client.uid, code: code,
                                   redirect_uri: redirect_uri, code_verifier: verifier }
  end

  def refresh(token)
    post "/oauth/token", params: { grant_type: "refresh_token", client_id: client.uid, refresh_token: token }
  end

  it "exchanges a code and then a refresh token for an approved client and active user" do
    redeem(issue_code)
    expect(response).to have_http_status(:ok)
    refresh_token = response.parsed_body.fetch("refresh_token")

    # Until TASK-019 adds jti, a token with the same claims in the same second
    # would collide with the one just issued.
    Timecop.travel(2.seconds.from_now) { refresh(refresh_token) }
    expect(response).to have_http_status(:ok)
    expect(response.parsed_body["access_token"]).to be_present
  end

  describe "a code issued before the change" do
    let!(:code) { issue_code }

    it "is refused with invalid_client once the client is revoked" do
      OAuth::Clients.revoke(client.uid, by: admin)
      redeem(code)
      expect(response).to have_http_status(:unauthorized)
      expect(response.parsed_body["error"]).to eq("invalid_client")
    end

    it "is refused with invalid_grant once the user is disabled" do
      user.update!(disabled_at: Time.current)
      redeem(code)
      expect(response).to have_http_status(:bad_request)
      expect(response.parsed_body["error"]).to eq("invalid_grant")
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
      expect(response).to have_http_status(:bad_request)
      expect(response.parsed_body["error"]).to eq("invalid_grant")
    end

    it "is refused once the user is disabled" do
      user.update!(disabled_at: Time.current)
      refresh(refresh_token)
      expect(response).to have_http_status(:bad_request)
      expect(response.parsed_body["error"]).to eq("invalid_grant")
    end
  end
end
