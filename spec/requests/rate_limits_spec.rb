require "rails_helper"
require "base64"
require "support/rate_limits"

# Request rate limits (TASK-028): Rails' rate_limit on the OAuth endpoints
# (OAuth::TokenEndpointLimits, ClientRegistrationsController) and on Devise's
# account forms (AccountRateLimits), counted in Rails.cache.
RSpec.describe "Rate limits", type: :request do
  include RateLimits

  let(:address) { "127.0.0.1" }

  describe "OAuth token endpoint" do
    let(:client) { create(:oauth_client, :public) }

    def token_request(client_id: client.uid, ip: address, headers: {})
      post "/oauth/token", params: { grant_type: "authorization_code", code: "nope", client_id: client_id,
                                     redirect_uri: "https://client.test/callback", code_verifier: "x" * 43 },
                           headers: headers, env: { "REMOTE_ADDR" => ip }
    end

    def spend(by, count: rate_limits.oauth_token, name: "create")
      spend_rate_limit(scope: "doorkeeper/tokens", name: name, by: by, count: count, within: 1.minute)
    end

    def expect_refused(window: "60")
      expect(response).to have_http_status(:too_many_requests)
      expect(response.parsed_body).to eq("error" => "temporarily_unavailable",
                                         "error_description" => "too many requests; try again later")
      expect(response.headers["retry-after"]).to eq(window)
      expect(response.headers["cache-control"]).to include("no-store")
    end

    it "allows the configured number of requests per approved client and address, then answers 429" do
      spend("#{client.uid}:#{address}", count: rate_limits.oauth_token - 1)
      token_request
      expect(response).to have_http_status(:bad_request) # the bogus code, not the limit

      token_request
      expect_refused
    end

    it "counts the same client from another address separately" do
      spend("#{client.uid}:#{address}")
      token_request
      expect_refused

      token_request(ip: "203.0.113.7")
      expect(response).to have_http_status(:bad_request)
    end

    it "reads the client from HTTP Basic as Doorkeeper does" do
      service = create(:oauth_client)
      spend("#{service.uid}:#{address}")
      token_request(client_id: nil,
                    headers: { "Authorization" => "Basic #{Base64.strict_encode64("#{service.uid}:wrong")}" })
      expect_refused
    end

    it "counts an unknown or unapproved client_id per address, so invented ids buy nothing" do
      spend(address)
      token_request(client_id: SecureRandom.hex(16))
      expect_refused
      token_request(client_id: create(:oauth_client, :public, :pending).uid)
      expect_refused

      token_request
      expect(response).to have_http_status(:bad_request)
    end

    it "lets requests through again after the window" do
      spend("#{client.uid}:#{address}")
      Timecop.travel(61.seconds.from_now) { token_request }
      expect(response).to have_http_status(:bad_request)
    end

    it "limits revocation and introspection with their own limits" do
      service = create(:oauth_client)
      auth = { "Authorization" => "Basic #{Base64.strict_encode64("#{service.uid}:#{service.plaintext_secret}")}" }

      spend("#{service.uid}:#{address}", name: "revoke", count: rate_limits.oauth_revoke)
      post "/oauth/revoke", params: { token: "x" }, headers: auth
      expect_refused

      spend("#{service.uid}:#{address}", name: "introspect", count: rate_limits.oauth_introspect - 1)
      post "/oauth/introspect", params: { token: "x" }, headers: auth
      expect(response).to have_http_status(:ok)
      post "/oauth/introspect", params: { token: "x" }, headers: auth
      expect_refused
    end
  end

  describe "sign-in" do
    let(:user) { create(:user, password: "correct horse battery") }

    def sign_in_attempt(email: user.email, ip: address)
      post user_session_path, params: { user: { email: email, password: "wrong password" } },
                              env: { "REMOTE_ADDR" => ip }
    end

    def spend(name, by, count)
      spend_rate_limit(scope: "devise/sessions", name: name, by: by, count: count, within: 1.minute)
    end

    def expect_form_refused(window: "60")
      expect(response).to have_http_status(:too_many_requests)
      expect(response.headers["retry-after"]).to eq(window)
      expect(response.body).to include("Too many attempts. Please wait a while and try again.")
      expect(response.body).to include("<form")
    end

    it "allows the configured attempts per address, then re-renders the form with 429" do
      spend("address", address, rate_limits.sign_in - 1)
      sign_in_attempt
      expect(response).to have_http_status(:unprocessable_content)

      sign_in_attempt(email: "someone-else@example.com")
      expect_form_refused
    end

    it "limits attempts per submitted email across addresses, normalised and hashed" do
      spend("email", Digest::SHA256.hexdigest(user.email.downcase), rate_limits.sign_in_email)
      sign_in_attempt(email: "  #{user.email.upcase} ", ip: "203.0.113.7")
      expect_form_refused

      sign_in_attempt(email: "someone-else@example.com", ip: "203.0.113.7")
      expect(response).to have_http_status(:unprocessable_content)
    end

    it "does not count a refused attempt towards the account lock" do
      spend("address", address, rate_limits.sign_in)
      expect { sign_in_attempt }.not_to(change { user.reload.failed_attempts })
    end
  end

  describe "account emails" do
    let(:user) { create(:user) }

    it "limits password-reset requests per address and per email, per hour, without sending mail" do
      spend_rate_limit(scope: "devise/passwords", name: "address", by: address,
                       count: rate_limits.account_mail, within: 1.hour)
      expect { post user_password_path, params: { user: { email: user.email } } }
        .not_to(change { ActionMailer::Base.deliveries.size })
      expect(response).to have_http_status(:too_many_requests)
      expect(response.headers["retry-after"]).to eq("3600")

      spend_rate_limit(scope: "devise/passwords", name: "email", by: Digest::SHA256.hexdigest(user.email),
                       count: rate_limits.account_mail_email, within: 1.hour)
      post user_password_path, params: { user: { email: user.email } }, env: { "REMOTE_ADDR" => "203.0.113.7" }
      expect(response).to have_http_status(:too_many_requests)
    end

    it "limits unlock-instruction requests the same way" do
      spend_rate_limit(scope: "devise/unlocks", name: "address", by: address,
                       count: rate_limits.account_mail, within: 1.hour)
      post user_unlock_path, params: { user: { email: user.email } }
      expect(response).to have_http_status(:too_many_requests)
      expect(response.body).to include("Too many attempts.")
    end

    it "limits confirmation-instruction requests the same way" do
      spend_rate_limit(scope: "devise/confirmations", name: "email", by: Digest::SHA256.hexdigest(user.email),
                       count: rate_limits.account_mail_email, within: 1.hour)
      expect { post user_confirmation_path, params: { user: { email: user.email } } }
        .not_to(change { ActionMailer::Base.deliveries.size })
      expect(response).to have_http_status(:too_many_requests)
    end

    it "still sends a reset email below the limit" do
      expect { post user_password_path, params: { user: { email: user.email } } }
        .to change { ActionMailer::Base.deliveries.size }.by(1)
    end
  end
end
