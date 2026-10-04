require "rails_helper"
require "base64"
require "support/hub_access_token"

# POST /oauth/register — RFC 7591 dynamic client registration (TASK-025),
# approval-gated by default behind OAUTH_REGISTRATION_POLICY.
RSpec.describe "OAuth dynamic client registration", type: :request do
  include HubAccessToken

  let(:admin) { create(:user, :admin) }
  let(:public_metadata) do
    { client_name: "Claude Desktop", redirect_uris: ["http://127.0.0.1:33418/callback"],
      token_endpoint_auth_method: "none", grant_types: %w[authorization_code refresh_token],
      response_types: ["code"], scope: "openid profile offline_access", software_id: "claude-desktop",
      software_version: "1.4.0", client_uri: "https://claude.example", logo_uri: "https://claude.example/logo.png",
      contacts: ["ops@claude.example"] }
  end
  let(:confidential_metadata) do
    { client_name: "Notes", redirect_uris: ["https://notes.example/callback"], scope: "openid email" }
  end

  def register(body)
    post "/oauth/register", params: body.is_a?(String) ? body : body.to_json,
                            headers: { "CONTENT_TYPE" => "application/json" }
  end

  def with_config(key, value)
    original = Rails.configuration.x.oauth.public_send(key)
    Rails.configuration.x.oauth.public_send(:"#{key}=", value)
    yield
  ensure
    Rails.configuration.x.oauth.public_send(:"#{key}=", original)
  end

  def expect_error(code, status: :bad_request)
    expect(response).to have_http_status(status)
    expect(response.parsed_body["error"]).to eq(code)
    expect(response.parsed_body["error_description"]).to be_present
    expect(response.parsed_body).not_to have_key("client_id")
  end

  describe "under the default approval policy" do
    it "registers a public client as pending and echoes its metadata" do
      register(public_metadata)
      expect(response).to have_http_status(:created)
      expect(response.headers["cache-control"]).to include("no-store")
      body = response.parsed_body
      client = OAuth::Clients.find(body.fetch("client_id"))
      expect(body).to eq(
        "client_id" => client.uid, "client_id_issued_at" => client.created_at.to_i,
        "client_name" => "Claude Desktop", "redirect_uris" => ["http://127.0.0.1:33418/callback"],
        "token_endpoint_auth_method" => "none", "grant_types" => %w[authorization_code refresh_token],
        "response_types" => ["code"], "scope" => "openid profile offline_access", "software_id" => "claude-desktop",
        "software_version" => "1.4.0", "client_uri" => "https://claude.example",
        "logo_uri" => "https://claude.example/logo.png", "contacts" => ["ops@claude.example"],
        "approval_state" => "pending",
        "approval_message" => "Registration received. An administrator must approve this client before it can " \
                              "sign users in."
      )
      expect(client).to have_attributes(client_type: "public", approval_state: "pending", registered_via: "dynamic",
                                        owner_id: nil, software_id: "claude-desktop", registration_ip: "127.0.0.1")
    end

    it "registers a confidential client with a one-time secret and RFC 7591 defaults" do
      register(confidential_metadata)
      expect(response).to have_http_status(:created)
      body = response.parsed_body
      expect(body).to include("token_endpoint_auth_method" => "client_secret_basic",
                              "grant_types" => ["authorization_code"], "response_types" => ["code"],
                              "client_secret_expires_at" => 0, "approval_state" => "pending")
      expect(body.fetch("client_secret")).to be_present
      expect(OAuth::Clients.find(body.fetch("client_id")).to_h.values).not_to include(body.fetch("client_secret"))

      # The secret authenticates the client (revocation of an unknown token: 200 only for a valid secret).
      OAuth::Clients.approve(body.fetch("client_id"), by: admin)
      { body.fetch("client_secret") => :ok, "wrong" => :forbidden }.each do |secret, status|
        auth = Base64.strict_encode64("#{body.fetch('client_id')}:#{secret}")
        post "/oauth/revoke", params: { token: "unknown" }, headers: { "Authorization" => "Basic #{auth}" }
        expect(response).to have_http_status(status)
      end
    end

    it "defaults the scope to openid" do
      register(confidential_metadata.except(:scope))
      expect(response.parsed_body["scope"]).to eq("openid")
    end

    it "ignores unknown fields" do
      register(public_metadata.merge(jwks_uri: "https://x.example/jwks", tos_uri: "https://x.example/tos"))
      expect(response).to have_http_status(:created)
      expect(response.parsed_body).not_to have_key("jwks_uri")
    end

    it "logs the registration with its client_id and source address" do
      allow(Rails.logger).to receive(:info).and_call_original
      register(public_metadata)
      expect(Rails.logger).to have_received(:info)
        .with(/\[oauth\.register\] client_id=#{response.parsed_body['client_id']} ip=127\.0\.0\.1 policy=approval/)
    end

    it "keeps a pending client away from the authorization endpoint until an administrator approves it" do
      user = create(:user)
      register(public_metadata)
      client_id = response.parsed_body.fetch("client_id")
      params = { client_id: client_id, redirect_uri: public_metadata[:redirect_uris].first, response_type: "code",
                 scope: "openid", code_challenge: HubAccessToken::CODE_CHALLENGE, code_challenge_method: "S256" }

      sign_in user
      get "/oauth/authorize", params: params
      expect(response).to have_http_status(:unauthorized)
      expect(response.body).to include("client is not authorized")

      OAuth::Clients.approve(client_id, by: admin)
      get "/oauth/authorize", params: params
      expect(response).to have_http_status(:ok)
      expect(response.body).to include("Claude Desktop")
    end
  end

  describe "validation" do
    {
      "a missing client_name" => [{ client_name: nil }, "invalid_client_metadata"],
      "a non-string client_name" => [{ client_name: 42 }, "invalid_client_metadata"],
      "missing redirect_uris" => [{ redirect_uris: nil }, "invalid_redirect_uri"],
      "an empty redirect_uris" => [{ redirect_uris: [] }, "invalid_redirect_uri"],
      "an http redirect URI off loopback" => [{ redirect_uris: ["http://evil.example/cb"] }, "invalid_redirect_uri"],
      "a redirect URI with a fragment" => [{ redirect_uris: ["https://a.example/cb#x"] }, "invalid_redirect_uri"],
      "the out-of-band redirect URI" => [{ redirect_uris: ["urn:ietf:wg:oauth:2.0:oob"] }, "invalid_redirect_uri"],
      "an unsupported auth method" => [{ token_endpoint_auth_method: "private_key_jwt" }, "invalid_client_metadata"],
      "the machine grant" => [{ grant_types: %w[authorization_code client_credentials] }, "invalid_client_metadata"],
      "grant_types without authorization_code" => [{ grant_types: ["refresh_token"] }, "invalid_client_metadata"],
      "the implicit response type" => [{ response_types: ["token"] }, "invalid_client_metadata"],
      "an admin scope" => [{ scope: "openid admin:clients" }, "invalid_client_metadata"],
      "a machine scope" => [{ scope: "openid introspect" }, "invalid_client_metadata"],
      "a scope outside the catalogue" => [{ scope: "openid write:all" }, "invalid_client_metadata"],
      "an http logo_uri" => [{ logo_uri: "http://claude.example/logo.png" }, "invalid_client_metadata"],
      "a javascript client_uri" => [{ client_uri: "javascript:alert(1)" }, "invalid_client_metadata"],
      "contacts that are not an array" => [{ contacts: "ops@claude.example" }, "invalid_client_metadata"]
    }.each do |label, (override, code)|
      it "refuses #{label} with #{code}" do
        register(public_metadata.merge(override))
        expect_error(code)
      end
    end

    it "refuses a body that is not a JSON object" do
      register("not json")
      expect_error("invalid_client_metadata")

      register("[]")
      expect_error("invalid_client_metadata")
    end

    it "refuses a body over 16 KiB with 413 before parsing it, on every path that reaches the endpoint" do
      large = public_metadata.merge(software_id: "x" * 17.kilobytes).to_json
      %w[/oauth/register /oauth/register/ //oauth//register].each do |path|
        expect do
          post path, params: large, headers: { "CONTENT_TYPE" => "application/json" }
        end.not_to(change { OAuth::Clients.list.size })
        expect(response).to have_http_status(:content_too_large)
        expect(response.parsed_body["error"]).to eq("invalid_request")
      end
    end

    it "has no format-suffixed variant of the endpoint" do
      post "/oauth/register.json", params: public_metadata.to_json, headers: { "CONTENT_TYPE" => "application/json" }
      expect(response).to have_http_status(:not_found)
    end

    it "creates nothing when it refuses" do
      expect { register(public_metadata.merge(scope: "admin:users")) }.not_to(change { OAuth::Clients.list.size })
    end
  end

  describe "abuse controls" do
    it "refuses the same client_name and redirect_uris again within 24 hours" do
      register(public_metadata)
      register(public_metadata.merge(redirect_uris: public_metadata[:redirect_uris].reverse))
      expect_error("invalid_client_metadata")
      expect(response.parsed_body["error_description"]).to include("last 24 hours")

      Timecop.travel(25.hours.from_now) { register(public_metadata) }
      expect(response).to have_http_status(:created)
    end

    it "caps registrations per source address and hour with 429" do
      with_config(:registration_ip_limit, 2) do
        2.times { |n| register(public_metadata.merge(client_name: "Agent #{n}")) }
        expect(response).to have_http_status(:created)

        register(public_metadata.merge(client_name: "Agent 3"))
        expect_error("temporarily_unavailable", status: :too_many_requests)
        expect(response.headers["retry-after"]).to eq("3600")

        Timecop.travel(61.minutes.from_now) { register(public_metadata.merge(client_name: "Agent 4")) }
        expect(response).to have_http_status(:created)
      end
    end
  end

  describe "under the open policy" do
    around { |example| with_config(:registration_policy, :open) { example.run } }

    it "approves a public client at once" do
      register(public_metadata)
      expect(response).to have_http_status(:created)
      expect(response.parsed_body).to include(
        "approval_state" => "approved", "approval_message" => "The client is registered and can be used now."
      )
      expect(OAuth::Clients.usable?(response.parsed_body.fetch("client_id"))).to be(true)
    end

    it "refuses a confidential client" do
      register(confidential_metadata)
      expect_error("invalid_client_metadata")
    end

    it "still refuses admin and machine scopes" do
      register(public_metadata.merge(scope: "openid admin:clients"))
      expect_error("invalid_client_metadata")

      register(public_metadata.merge(scope: "introspect"))
      expect_error("invalid_client_metadata")
    end
  end

  describe "under the closed policy" do
    around { |example| with_config(:registration_policy, :closed) { example.run } }

    it "has no endpoint and is not advertised" do
      expect { register(public_metadata) }.not_to(change { OAuth::Clients.list.size })
      expect(response).to have_http_status(:not_found)

      %w[openid-configuration oauth-authorization-server].each do |document|
        get "/.well-known/#{document}"
        expect(response.parsed_body).not_to have_key("registration_endpoint")
      end
    end
  end
end
