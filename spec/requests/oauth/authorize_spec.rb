require "rails_helper"
require "base64"
require "digest"

# GET/POST /oauth/authorize — the HTTP contract of the authorization endpoint
# (TASK-017): PKCE, redirect allow-list, resource indicator (RFC 8707), client
# state, disabled accounts and the RFC 6749 §4.1.2.1 error codes. The consent
# page and persisted consents are spec/requests/oauth/consent_spec.rb; here the
# GET shows the consent page and the POST is the user's approval.
RSpec.describe "OAuth authorization endpoint", type: :request do
  let(:user) { create(:user) }
  let(:redirect_uri) { "https://client.test/callback" }
  let(:public_client) { create(:oauth_client, :public, redirect_uri: redirect_uri) }
  let(:confidential_client) { create(:oauth_client, redirect_uri: redirect_uri) }
  let(:verifier) { "a" * 43 }
  let(:challenge) { Base64.urlsafe_encode64(Digest::SHA256.digest(verifier), padding: false) }
  let(:state) { "st@te with spaces&=" }

  def params_for(client, **overrides)
    {
      client_id: client.uid, redirect_uri: redirect_uri, response_type: "code", scope: "openid profile",
      state: state, code_challenge: challenge, code_challenge_method: "S256"
    }.merge(overrides).compact
  end

  def authorize(client, **overrides)
    get "/oauth/authorize", params: params_for(client, **overrides)
  end

  def approve(client, **overrides)
    post "/oauth/authorize", params: params_for(client, **overrides)
  end

  # The client-side view of a redirect back: base URI and decoded query.
  def callback
    uri = URI.parse(response.location)
    query = Rack::Utils.parse_query(uri.query)
    uri.query = nil
    [uri.to_s, query]
  end

  def expect_redirect_error(code)
    expect(response).to have_http_status(:found)
    base, query = callback
    expect(base).to eq(redirect_uri)
    expect(query).to include("error" => code, "state" => state)
    expect(query["error_description"]).to be_present
    query
  end

  def expect_rendered_error(status, description)
    expect(response).to have_http_status(status)
    expect(response.location).to be_nil
    expect(response.body).to include(description)
  end

  describe "signed out" do
    it "redirects to sign-in and returns to the authorization request afterwards" do
      path = "/oauth/authorize?#{params_for(public_client).to_query}"
      get path
      expect(response).to redirect_to(new_user_session_path)

      post user_session_path, params: { user: { email: user.email, password: user.password } }
      expect(response).to redirect_to(path)
    end
  end

  describe "happy path" do
    before { sign_in user }

    it "shows the consent form to a public client with S256 PKCE" do
      authorize(public_client)
      expect(response).to have_http_status(:ok)
      expect(response.body).to include(public_client.name)
    end

    it "issues a code with the state echoed untouched once the user approves" do
      approve(public_client)
      expect(response).to have_http_status(:found)
      base, query = callback
      expect(base).to eq(redirect_uri)
      expect(query["code"]).to be_present
      expect(query["state"]).to eq(state)
      expect(query).not_to have_key("error")

      grant = OAuth::Grants.for(user: user).sole
      expect(grant).to have_attributes(client_uid: public_client.uid, code_challenge_method: "S256",
                                       resource: nil, scopes: %w[openid profile])
    end

    it "lets a confidential client skip PKCE" do
      approve(confidential_client, code_challenge: nil, code_challenge_method: nil)
      expect(callback.last).to include("code", "state")
      expect(OAuth::Grants.for(user: user).sole.code_challenge_method).to be_nil
    end

    it "honours PKCE when a confidential client sends it" do
      approve(confidential_client)
      expect(callback.last).to include("code")
      expect(OAuth::Grants.for(user: user).sole.code_challenge_method).to eq("S256")
    end
  end

  describe "PKCE" do
    before { sign_in user }

    it "refuses a public client without a code_challenge" do
      authorize(public_client, code_challenge: nil, code_challenge_method: nil)
      query = expect_redirect_error("invalid_request")
      expect(query["error_description"]).to eq("Code challenge is required.")
    end

    it "refuses a public client with a challenge but no method" do
      authorize(public_client, code_challenge_method: nil)
      query = expect_redirect_error("invalid_request")
      expect(query["error_description"]).to eq("The code_challenge_method must be S256.")
    end

    it "never accepts the plain method, even for a confidential client" do
      authorize(public_client, code_challenge: verifier, code_challenge_method: "plain")
      expect(expect_redirect_error("invalid_request")["error_description"]).to include("S256")

      authorize(confidential_client, code_challenge: verifier, code_challenge_method: "plain")
      expect(expect_redirect_error("invalid_request")["error_description"]).to include("S256")
    end

    it "refuses a malformed challenge" do
      authorize(public_client, code_challenge: "too short")
      expect(expect_redirect_error("invalid_request")["error_description"]).to include("43 to 128")
    end
  end

  describe "redirect_uri allow-list" do
    before { sign_in user }

    {
      "a different path" => "https://client.test/callback2",
      "an extra query parameter" => "https://client.test/callback?next=1",
      "a trailing slash" => "https://client.test/callback/",
      "a different scheme" => "http://client.test/callback",
      "an unregistered host" => "https://evil.test/callback"
    }.each do |label, uri|
      it "renders the error page (never redirects) for #{label}" do
        authorize(public_client, redirect_uri: uri)
        expect_rendered_error(:bad_request, "redirect URI")
      end
    end

    it "renders the error page when redirect_uri is missing" do
      authorize(public_client, redirect_uri: nil)
      expect_rendered_error(:bad_request, "redirect URI")
    end

    it "ignores only the port of a loopback redirect_uri (RFC 8252 §7.3)" do
      native = create(:oauth_client, :public, redirect_uri: "http://127.0.0.1/cb")
      authorize(native, redirect_uri: "http://127.0.0.1:49152/cb")
      expect(response).to have_http_status(:ok)

      authorize(native, redirect_uri: "http://127.0.0.1:49152/cb?x=1")
      expect_rendered_error(:bad_request, "redirect URI")
    end
  end

  describe "client" do
    before { sign_in user }

    it "renders the error page for an unknown client_id" do
      authorize(public_client, client_id: "nope")
      expect_rendered_error(:unauthorized, "unknown client")
    end

    it "renders the error page when client_id is missing" do
      authorize(public_client, client_id: nil)
      expect_rendered_error(:bad_request, "client_id")
    end

    it "refuses a pending client with unauthorized_client" do
      authorize(create(:oauth_client, :public, :pending, redirect_uri: redirect_uri))
      expect_rendered_error(:unauthorized, "client is not authorized")
    end

    it "refuses a revoked client with unauthorized_client" do
      authorize(create(:oauth_client, :public, :revoked, redirect_uri: redirect_uri))
      expect_rendered_error(:unauthorized, "client is not authorized")
    end
  end

  describe "disabled user" do
    let(:user) { create(:user, disabled_at: 1.day.ago) }

    before { sign_in user }

    it "signs the user out and sends access_denied to the client" do
      authorize(public_client)
      expect_redirect_error("access_denied")

      authorize(public_client)
      expect(response).to redirect_to(new_user_session_path)
    end

    it "renders access_denied rather than redirecting to an unverified redirect_uri" do
      authorize(public_client, redirect_uri: "https://evil.test/callback")
      expect_rendered_error(:bad_request, "redirect URI")

      authorize(public_client)
      expect(response).to redirect_to(new_user_session_path)
    end
  end

  describe "response_type and scopes" do
    before { sign_in user }

    it "refuses the implicit flow" do
      authorize(public_client, response_type: "token")
      expect_redirect_error("unsupported_response_type")
    end

    it "refuses a scope the client was not registered with" do
      authorize(public_client, scope: "openid email")
      expect_redirect_error("invalid_scope")
    end

    it "refuses a scope outside the catalogue" do
      authorize(public_client, scope: "openid bogus")
      expect_redirect_error("invalid_scope")
    end
  end

  describe "resource indicator (RFC 8707)" do
    before { sign_in user }

    it "persists a known resource on the grant and carries it to the token" do
      approve(public_client, resource: OAuth::Resources.hub_api)
      code = callback.last.fetch("code")
      expect(OAuth::Grants.for(user: user).sole.resource).to eq(OAuth::Resources.hub_api)

      post "/oauth/token", params: { grant_type: "authorization_code", client_id: public_client.uid, code: code,
                                     redirect_uri: redirect_uri, code_verifier: verifier }
      expect(response).to have_http_status(:ok)
      expect(response.parsed_body["access_token"]).to be_present
      expect(OAuth::Tokens.active_for(user: user).sole.resource).to eq(OAuth::Resources.hub_api)
    end

    it "accepts the MCP resource" do
      authorize(public_client, resource: OAuth::Resources.hub_mcp)
      expect(response).to have_http_status(:ok)
    end

    {
      "an unknown resource" => "https://other.test/api",
      "a relative reference" => "api",
      "a fragment" => "#{ENV.fetch('HUB_ISSUER')}/api#users",
      "an empty value" => ""
    }.each do |label, value|
      it "rejects #{label} with invalid_target" do
        authorize(public_client, resource: value)
        expect_redirect_error("invalid_target")
      end
    end
  end
end
