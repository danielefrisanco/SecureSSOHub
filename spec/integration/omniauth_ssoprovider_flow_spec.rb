require "rails_helper"
require "support/omniauth_client_flow"

# The proof that the hub honours the contract of its own client gem (TASK-023):
# omniauth-ssoprovider as shipped (0.1.2), mounted in a minimal client app,
# completes an authorization-code + PKCE login against the in-process hub —
# sign-in, consent, token exchange, /api/v1/userinfo — and hands the client
# the hub's user and an access token that verifies against the hub's JWKS.
# Gem gaps found here are TODO T44/T45 rows; the gem itself is not touched.
RSpec.describe "omniauth-ssoprovider login against the hub", type: :request do
  include OmniauthClientFlow

  let(:user) { create(:user, name: "Ada Lovelace") }
  let(:client) do
    create(:oauth_client, name: "Notes", redirect_uri: OmniauthClientFlow::CALLBACK_URL, scopes: "openid profile email")
  end
  let(:browser) { client_browser(omniauth_client_app(client)) }
  let(:hub_api) { OAuth::Resources.hub_api }

  before { route_hub_over_http }

  def query(url)
    Rack::Utils.parse_query(URI.parse(url).query)
  end

  def failure_message(client_response)
    expect(client_response.status).to eq(302)
    location = URI.parse(client_response.location)
    expect(location.path).to eq("/auth/failure")
    query(client_response.location).fetch("message")
  end

  def verify_with_jwks(jwt)
    get "#{OmniauthClientFlow::HUB_ORIGIN}/.well-known/jwks.json"
    JWT.decode(jwt, nil, true, algorithms: ["RS256"], jwks: JWT::JWK::Set.new(response.parsed_body)).first
  end

  it "sends the browser to the hub's authorization endpoint with PKCE, state and the requested scope" do
    authorize_url = start_login(browser)

    expect(authorize_url).to start_with("https://hub.test/oauth/authorize?")
    expect(query(authorize_url)).to include(
      "response_type" => "code", "client_id" => client.uid, "redirect_uri" => OmniauthClientFlow::CALLBACK_URL,
      "scope" => "openid profile email", "code_challenge_method" => "S256", "resource" => hub_api
    )
    expect(query(authorize_url)["state"]).to be_present
    expect(query(authorize_url)["code_challenge"]).to match(/\A[A-Za-z0-9_-]{43}\z/)
  end

  it "completes the login and hands the client the hub's user and a verifiable access token" do
    authorize_url = start_login(browser)
    callback_url = authorize_at_hub(authorize_url, user: user)

    expect(callback_url).to start_with(OmniauthClientFlow::CALLBACK_URL)
    expect(query(callback_url).keys).to contain_exactly("code", "state")
    expect(query(callback_url)["state"]).to eq(query(authorize_url)["state"])

    client_response = finish_login(browser, callback_url)
    expect(client_response.status).to eq(200)
    auth = JSON.parse(client_response.body)

    expect(auth).to include("provider" => "ssoprovider", "uid" => user.sso_id,
                            "info" => { "name" => "Ada Lovelace", "email" => user.email })
    expect(auth.dig("extra", "raw_info")).to eq(
      "id" => user.sso_id, "sub" => user.sso_id, "name" => "Ada Lovelace", "email" => user.email,
      "email_verified" => false, "roles" => []
    )
    expect(verify_with_jwks(auth.dig("extra", "access_token"))).to include(
      "iss" => "https://hub.test", "sub" => user.sso_id, "aud" => hub_api, "azp" => client.uid,
      "scope" => "openid profile email"
    )

    expect(a_request(:post, "https://hub.test/oauth/token").with(headers: { "Authorization" => /\ABasic / }))
      .to have_been_made.once
    expect(a_request(:get, "https://hub.test/api/v1/userinfo")).to have_been_made.once
  end

  # The auth hash 0.1.2 renders, key by key: what omniauth_syncer and other
  # consumers can rely on today (compared with omniauth_syncer's
  # auth_hash_0_1_2.json fixture in TODO T45).
  it "renders the auth hash shape of 0.1.2" do
    auth = JSON.parse(finish_login(browser, authorize_at_hub(start_login(browser), user: user)).body)

    expect(auth.keys).to contain_exactly("provider", "uid", "info", "credentials", "extra")
    expect(auth["credentials"].keys).to contain_exactly("token", "expires", "expires_at")
    expect(auth["credentials"]).to include("token" => auth.dig("extra", "access_token"), "expires" => true)
    expect(auth["extra"].keys).to contain_exactly("raw_info", "access_token")
  end

  describe "failures" do
    it "refuses a callback whose state was tampered with (csrf_detected), without calling the hub" do
      callback_url = authorize_at_hub(start_login(browser), user: user)
      tampered = callback_url.sub(/state=[^&]+/, "state=forged")

      expect(failure_message(finish_login(browser, tampered))).to eq("csrf_detected")
      expect(a_request(:post, "https://hub.test/oauth/token")).not_to have_been_made
    end

    it "reports a denied consent as access_denied" do
      callback_url = authorize_at_hub(start_login(browser), user: user, consent: :deny)

      expect(query(callback_url)).to include("error" => "access_denied")
      expect(failure_message(finish_login(browser, callback_url))).to eq("access_denied")
    end

    # unauthorized_client is never redirected (Doorkeeper: a client that is
    # not approved does not get its redirect_uri trusted), so the client app
    # never sees it — the user stays on the hub's error page.
    it "stops a pending client at the hub with unauthorized_client" do
      pending_client = create(:oauth_client, :pending, redirect_uri: OmniauthClientFlow::CALLBACK_URL,
                                                       scopes: "openid profile email")
      pending_browser = client_browser(omniauth_client_app(pending_client))

      expect(authorize_at_hub(start_login(pending_browser), user: user)).to be_nil
      expect(response).to have_http_status(:unauthorized)
      expect(response.body).to include("client is not authorized")
      expect(a_request(:post, "https://hub.test/oauth/token")).not_to have_been_made
    end
  end
end
