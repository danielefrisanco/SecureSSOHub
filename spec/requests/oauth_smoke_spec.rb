require "rails_helper"

# Doorkeeper + OpenID Connect are mounted and configured as TASK-014 specifies.
# Behaviour of the endpoints themselves is covered by the Phase 1 tasks that
# follow (authorize, consent, token, userinfo, discovery, revocation).
RSpec.describe "OAuth core installation", type: :request do
  describe "GET /oauth/authorize" do
    it "sends a signed-out visitor to sign-in" do
      get "/oauth/authorize"
      expect(response).to redirect_to(new_user_session_path)
    end

    it "is mounted and rejects a request without client parameters" do
      sign_in create(:user)
      get "/oauth/authorize"
      expect(response).to have_http_status(:bad_request)
      expect(response.body).to include("client_id")
    end
  end

  describe "GET /.well-known/openid-configuration" do
    it "advertises the configured issuer" do
      get "/.well-known/openid-configuration"
      expect(response).to have_http_status(:ok)
      expect(response.media_type).to eq("application/json")
      # Endpoint URLs still derive from the request host; TASK-021 rebuilds the
      # document from HUB_ISSUER.
      expect(response.parsed_body).to include("issuer" => ENV.fetch("HUB_ISSUER"))
      expect(response.parsed_body["token_endpoint"]).to end_with("/oauth/token")
    end
  end

  describe "schema" do
    it "has the Doorkeeper and OpenID Connect tables" do
      tables = ActiveRecord::Base.connection.tables
      expect(tables).to include("oauth_applications", "oauth_access_grants", "oauth_access_tokens",
                                "oauth_openid_requests")
    end
  end

  describe "configuration" do
    let(:config) { Doorkeeper.configuration }

    it "matches the hub's policy" do
      expect(config.access_token_expires_in).to eq(10.minutes.to_i)
      expect(config.authorization_code_expires_in).to eq(1.minute.to_i)
      expect(config.refresh_token_enabled?).to be(true)
      expect(config.grant_flows).to contain_exactly("authorization_code", "client_credentials")
      expect(config.force_pkce?).to be(true)
      expect(config.enforce_configured_scopes?).to be(true)
      expect(config.access_token_generator).to eq("::Doorkeeper::JWT")
      expect(config.token_secret_strategy).to eq(Doorkeeper::SecretStoring::Sha256Hash)
      expect(config.application_secret_strategy).to eq(Doorkeeper::SecretStoring::Sha256Hash)
    end

    it "takes its scopes from config/oauth_scopes.yml" do
      catalogue = Rails.application.config_for(:oauth_scopes).fetch(:scopes)
      expect(config.default_scopes.to_a).to eq(["openid"])
      expect(config.optional_scopes.to_a).to match_array(catalogue.keys.map(&:to_s) - ["openid"])
    end

    it "signs with an RSA key shared by doorkeeper-jwt and openid_connect" do
      pem = Rails.application.config.x.oauth.signing_key_pem
      expect(OpenSSL::PKey::RSA.new(pem).n.num_bits).to be >= 2048
      expect(Doorkeeper::JWT.configuration.secret_key).to eq(pem)
      expect(Doorkeeper::OpenidConnect.configuration.signing_key).to eq(pem)
    end
  end
end
