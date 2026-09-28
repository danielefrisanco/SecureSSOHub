require "rails_helper"
require "base64"
require "digest"

# The consent page on GET /oauth/authorize and the persisted consent behind it
# (TASK-018). The request contract itself (PKCE, redirect allow-list, resource,
# state) is spec/requests/oauth/authorize_spec.rb.
RSpec.describe "OAuth consent", type: :request do
  let(:user) { create(:user) }
  let(:redirect_uri) { "https://client.test/callback" }
  let(:client) { create(:oauth_client, :public, redirect_uri: redirect_uri, scopes: "openid profile email") }
  let(:verifier) { "a" * 43 }
  let(:challenge) { Base64.urlsafe_encode64(Digest::SHA256.digest(verifier), padding: false) }
  let(:state) { "st@te" }

  before { sign_in user }

  def params_for(client, **overrides)
    {
      client_id: client.uid, redirect_uri: redirect_uri, response_type: "code", scope: "openid profile",
      state: state, code_challenge: challenge, code_challenge_method: "S256"
    }.merge(overrides).compact
  end

  def authorize(client, **overrides)
    get "/oauth/authorize", params: params_for(client, **overrides)
  end

  def callback_query
    Rack::Utils.parse_query(URI.parse(response.location).query)
  end

  def page
    response.parsed_body
  end

  # The hidden fields of the Allow (or Deny) form, as the browser would send them.
  def form_params(form)
    form.css("input[type=hidden]").to_h { |input| [input["name"], input["value"]] }
  end

  def allow_form
    page.css(".consent-actions form").find { |form| form_params(form)["_method"].nil? }
  end

  def deny_form
    page.css(".consent-actions form").find { |form| form_params(form)["_method"] == "delete" }
  end

  def consented_scopes
    OAuth::Consents.granted_scopes(user: user, client_uid: client.uid)
  end

  describe "first visit" do
    it "renders the consent page in the application layout with the client and the scope descriptions" do
      authorize(client)

      expect(response).to have_http_status(:ok)
      expect(response.body).to include("Secure SSO Hub", client.name, user.email)
      expect(page.css("#oauth-permissions li").map { |li| li.text.squish }).to eq(["Sign you in", "See your name"])
      expect(page.css("#oauth-permissions .consent-new")).to be_empty
      expect(page.css("input[type=submit]").pluck("value")).to eq(%w[Allow Deny])
      expect(response.body).to include("revoke this later", "Not you? Sign out")
      expect(consented_scopes).to eq([])
    end

    it "renders under the CSP: no inline style, every script carries the nonce" do
      authorize(client)

      csp = response.headers["Content-Security-Policy"]
      expect(csp).to include("script-src 'self' 'nonce-", "img-src 'self' data: https:")
      expect(response.body).not_to match(/<style\b|\sstyle=|\son\w+=/)
      expect(page.css("script").pluck("nonce")).to all(be_present)
    end

    # Browsers check form-action against the redirect that follows the submit.
    it "admits the client's redirect target in form-action" do
      authorize(client)
      expect(response.headers["Content-Security-Policy"]).to include("form-action 'self' https://client.test;")

      native = create(:oauth_client, :public, redirect_uri: "com.example.app:/callback http://127.0.0.1/cb")
      authorize(native, redirect_uri: "com.example.app:/callback")
      expect(response.headers["Content-Security-Policy"]).to include("form-action 'self' com.example.app:;")

      authorize(native, redirect_uri: "http://127.0.0.1:49152/cb")
      expect(response.headers["Content-Security-Policy"]).to include("form-action 'self' http://127.0.0.1:49152;")
    end

    it "keeps form-action to the hub itself on the error page" do
      authorize(client, redirect_uri: "https://evil.test/callback")
      expect(response).to have_http_status(:bad_request)
      expect(response.headers["Content-Security-Policy"]).to include("form-action 'self';")
    end

    it "carries every request parameter, resource included, into the Allow and Deny forms" do
      authorize(client, resource: OAuth::Resources.hub_api, nonce: "n-0nce")

      expected = { "client_id" => client.uid, "redirect_uri" => redirect_uri, "state" => state,
                   "response_type" => "code", "scope" => "openid profile", "code_challenge" => challenge,
                   "code_challenge_method" => "S256", "resource" => OAuth::Resources.hub_api, "nonce" => "n-0nce" }
      expect(form_params(allow_form)).to include(expected)
      expect(form_params(deny_form)).to include(expected.merge("_method" => "delete"))
    end

    it "omits blank parameters from the forms (an empty resource would be an invalid_target)" do
      authorize(client, state: nil)
      expect(form_params(allow_form).keys).not_to include("resource", "nonce", "state")
      expect(form_params(allow_form)).to include("scope" => "openid profile", "response_mode" => "query")
    end

    it "shows an https logo and ignores any other" do
      logo = create(:oauth_client, :public, redirect_uri: redirect_uri, logo_uri: "https://client.test/logo.png")
      authorize(logo)
      expect(page.css("img.consent-logo").first["src"]).to eq("https://client.test/logo.png")

      plain = create(:oauth_client, :public, redirect_uri: redirect_uri, logo_uri: "http://client.test/logo.png")
      authorize(plain)
      expect(page.css("img.consent-logo")).to be_empty
    end
  end

  describe "Allow" do
    it "persists the consent and redirects to the client with a code" do
      authorize(client)
      post "/oauth/authorize", params: form_params(allow_form)

      expect(response).to have_http_status(:found)
      expect(response.location).to start_with(redirect_uri)
      expect(callback_query).to include("code", "state" => state)
      expect(consented_scopes).to eq(%w[openid profile])
      expect(OAuth::Grants.for(user: user).sole).to have_attributes(scopes: %w[openid profile], resource: nil)
    end

    it "carries the resource indicator to the grant" do
      authorize(client, resource: OAuth::Resources.hub_api)
      post "/oauth/authorize", params: form_params(allow_form)

      expect(callback_query).to include("code")
      expect(OAuth::Grants.for(user: user).sole.resource).to eq(OAuth::Resources.hub_api)
    end
  end

  describe "Deny" do
    it "redirects with access_denied and persists nothing" do
      authorize(client)
      delete "/oauth/authorize", params: form_params(deny_form).except("_method")

      expect(response).to have_http_status(:found)
      expect(response.location).to start_with(redirect_uri)
      expect(callback_query).to include("error" => "access_denied", "state" => state)
      expect(callback_query).not_to have_key("code")
      expect(consented_scopes).to eq([])
      expect(OAuth::Grants.for(user: user)).to be_empty
    end
  end

  describe "repeat visit" do
    before { OAuth::Consents.grant(user: user, client_uid: client.uid, scopes: %w[openid profile]) }

    it "skips the page for the same scopes and issues the code at once" do
      authorize(client)

      expect(response).to have_http_status(:found)
      expect(callback_query).to include("code", "state" => state)
      expect(OAuth::Grants.for(user: user).sole.scopes).to eq(%w[openid profile])
    end

    it "skips the page for a subset of the consented scopes" do
      authorize(client, scope: "openid")

      expect(response).to have_http_status(:found)
      expect(callback_query).to include("code")
      expect(consented_scopes).to eq(%w[openid profile])
    end

    it "asks again for a superset, highlighting only the new scopes" do
      authorize(client, scope: "openid profile email")

      expect(response).to have_http_status(:ok)
      expect(page.css("#oauth-permissions li").pluck("data-scope")).to eq(%w[openid profile email])
      expect(page.css("#oauth-permissions .consent-new").pluck("data-scope")).to eq(%w[email])
      expect(page.css("#oauth-permissions .badge").map(&:text)).to eq(%w[new])

      post "/oauth/authorize", params: form_params(allow_form)
      expect(callback_query).to include("code")
      expect(consented_scopes).to eq(%w[openid profile email])
    end

    it "asks again once the consent was revoked" do
      OAuth::Consents.revoke(user: user, client_uid: client.uid)
      authorize(client)

      expect(response).to have_http_status(:ok)
      expect(page.css("#oauth-permissions .consent-new")).to be_empty
    end

    it "asks another user" do
      sign_in create(:user)
      authorize(client)
      expect(response).to have_http_status(:ok)
    end
  end

  describe "admin scopes" do
    let(:admin_client) { create(:oauth_client, :public, redirect_uri: redirect_uri, scopes: "openid admin:clients") }

    it "refuses a non-admin with invalid_scope" do
      authorize(admin_client, scope: "openid admin:clients")

      expect(response).to have_http_status(:found)
      expect(callback_query).to include("error" => "invalid_scope", "state" => state)
      expect(callback_query["error_description"]).to be_present
      expect(consented_scopes).to eq([])
    end

    it "refuses a non-admin approving directly" do
      post "/oauth/authorize", params: params_for(admin_client, scope: "openid admin:clients")
      expect(callback_query).to include("error" => "invalid_scope")
      expect(OAuth::Grants.for(user: user)).to be_empty
    end

    it "asks an administrator for consent" do
      sign_in create(:user, :admin)
      authorize(admin_client, scope: "openid admin:clients")

      expect(response).to have_http_status(:ok)
      expect(page.css("#oauth-permissions li").map { |li| li.text.squish })
        .to eq(["Sign you in", "Manage OAuth clients on your behalf"])
    end
  end
end
