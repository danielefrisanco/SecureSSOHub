require "rails_helper"
require "base64"
require "support/hub_access_token"

# The audit log over HTTP (TASK-029): sign-in, failed sign-in and sign-out
# events from Warden, token issuance through every grant, the revocation
# endpoint, refresh-token reuse and code replay, the consent given at the
# authorization endpoint — each with the request's address and id. And the
# rule above all: no password, code, token or client secret ever reaches it.
RSpec.describe "Audit log", type: :request do
  include HubAccessToken

  let(:password) { "correct horse battery staple" }
  let(:user) { create(:user, password: password) }
  let(:client) { create(:oauth_client, :public, scopes: "openid offline_access") }
  let(:service) { create(:oauth_client, :machine) }

  def last_event(name)
    AuditEvent.where(event: name).order(:id).last
  end

  def sign_in_with(email, typed_password)
    # The route helper loads the routes; on a cold process a bare path would
    # reach Warden before Devise configured it (pre-existing, see TASK-029 notes).
    post user_session_path, params: { user: { email: email, password: typed_password } }
  end

  def issue_code(scope: "openid offline_access")
    sign_in user
    post "/oauth/authorize", params: { client_id: client.uid, redirect_uri: client.redirect_uri, response_type: "code",
                                       scope: scope, code_challenge: HubAccessToken::CODE_CHALLENGE,
                                       code_challenge_method: "S256" }
    sign_out user
    Rack::Utils.parse_query(URI.parse(response.location).query).fetch("code")
  end

  def redeem(code)
    post "/oauth/token", params: { grant_type: "authorization_code", client_id: client.uid, code: code,
                                   redirect_uri: client.redirect_uri, code_verifier: HubAccessToken::CODE_VERIFIER }
    response.parsed_body
  end

  def refresh(refresh_token)
    post "/oauth/token", params: { grant_type: "refresh_token", client_id: client.uid, refresh_token: refresh_token }
    response.parsed_body
  end

  def machine_token
    credentials = Base64.strict_encode64("#{service.uid}:#{service.plaintext_secret}")
    post "/oauth/token", params: { grant_type: "client_credentials", scope: "introspect" },
                         headers: { "Authorization" => "Basic #{credentials}" }
    response.parsed_body
  end

  def jti(access_token)
    JWT.decode(access_token, nil, false).first.fetch("jti")
  end

  describe "signing in and out" do
    it "records a sign-in with the strategy, the address and the request id" do
      sign_in_with(user.email, password)

      event = last_event("user.signed_in")
      expect(event).to have_attributes(actor_id: user.id, subject_id: user.id, ip: IPAddr.new("127.0.0.1"))
      expect(event.request_id).to eq(response.headers["x-request-id"])
      expect(event.metadata).to eq("strategy" => "database_authenticatable")
    end

    it "records a wrong password against the account, without what was typed" do
      sign_in_with(user.email, "wrong guess")

      event = last_event("user.sign_in_failed")
      expect(event).to have_attributes(actor_id: nil, subject_id: user.id)
      expect(event.metadata).to eq("reason" => "invalid")
      expect(event.attributes.to_json).not_to include("wrong guess")
    end

    it "records an unknown email without naming an account or storing the email" do
      sign_in_with("nobody@example.com", "wrong guess")

      event = last_event("user.sign_in_failed")
      expect(event.subject_id).to be_nil
      expect(event.attributes.to_json).not_to include("nobody@example.com")
    end

    it "records a locked account's attempt" do
      user.lock_access!(send_instructions: false)
      sign_in_with(user.email, password)

      expect(last_event("user.sign_in_failed")).to have_attributes(subject_id: user.id)
      expect(last_event("user.sign_in_failed").metadata).to eq("reason" => "locked")
      expect(last_event("user.signed_in")).to be_nil
    end

    it "does not count a signed-out visit to a protected page as a failed sign-in" do
      get "/oauth/authorize", params: { client_id: client.uid, response_type: "code" }
      expect(response).to redirect_to("/users/sign_in")
      expect(last_event("user.sign_in_failed")).to be_nil
    end

    it "records a sign-out" do
      sign_in_with(user.email, password)
      delete "/users/sign_out"
      expect(last_event("user.signed_out")).to have_attributes(actor_id: user.id, subject_id: user.id)
    end
  end

  describe "token issuance and revocation" do
    it "records the consent given at the authorization endpoint" do
      issue_code
      expect(last_event("consent.granted")).to have_attributes(actor_id: user.id, subject_id: user.id,
                                                               client_uid: client.uid)
    end

    it "records the code exchange and each refresh, by jti" do
      first = redeem(issue_code)
      issued = last_event("token.issued")
      expect(issued).to have_attributes(actor_id: nil, subject_id: user.id, client_uid: client.uid,
                                        jti: jti(first["access_token"]))
      expect(issued.metadata).to eq("grant_type" => "authorization_code", "scopes" => %w[openid offline_access])

      second = refresh(first["refresh_token"])
      expect(last_event("token.issued")).to have_attributes(jti: jti(second["access_token"]))
      expect(last_event("token.issued").metadata).to include("grant_type" => "refresh_token")
    end

    it "records a machine token" do
      token = machine_token.fetch("access_token")
      expect(last_event("token.issued")).to have_attributes(subject_id: nil, client_uid: service.uid, jti: jti(token))
      expect(last_event("token.issued").metadata).to eq("grant_type" => "client_credentials",
                                                        "scopes" => %w[introspect])
    end

    it "records a client revoking its token through the revocation endpoint" do
      access_token = redeem(issue_code).fetch("access_token")
      post "/oauth/revoke", params: { token: access_token, client_id: client.uid }

      expect(last_event("token.revoked")).to have_attributes(actor_id: nil, subject_id: user.id,
                                                             client_uid: client.uid, jti: jti(access_token))
    end

    it "records a reused refresh token" do
      first = redeem(issue_code)
      second = refresh(first["refresh_token"])
      refresh(first["refresh_token"])

      expect(last_event("token.refresh_reuse_detected")).to have_attributes(
        subject_id: user.id, client_uid: client.uid, jti: jti(first["access_token"])
      )
      expect(last_event("token.refresh_reuse_detected").metadata).to include("revoked" => 1)
      expect(OAuth::Tokens.active?(jti: jti(second["access_token"]))).to be(false)
    end

    it "records a replayed code" do
      code = issue_code
      redeem(code)
      redeem(code)

      expect(last_event("token.code_replay_detected")).to have_attributes(subject_id: user.id, client_uid: client.uid)
      expect(last_event("token.code_replay_detected").metadata).to include("revoked" => 1)
    end
  end

  it "never stores a password, code, token or client secret" do
    admin = create(:user, :admin)
    confidential = OAuth::Clients.create(name: "Billing", redirect_uris: ["https://billing.test/cb"],
                                         client_type: :confidential, scopes: %w[openid], by: admin)
    rotated = OAuth::Clients.rotate_secret(confidential.client.uid, by: admin)
    sign_in_with(user.email, "a mistyped #{password}")
    sign_in_with(user.email, password)
    delete "/users/sign_out"
    code = issue_code
    tokens = redeem(code)
    refreshed = refresh(tokens["refresh_token"])
    machine = machine_token
    post "/oauth/revoke", params: { token: refreshed["refresh_token"], client_id: client.uid }
    user.update!(password: "a brand new passphrase")

    credentials = [password, "a brand new passphrase", code, service.plaintext_secret, confidential.secret,
                   rotated.secret, *tokens.values_at("access_token", "refresh_token", "id_token"),
                   *refreshed.values_at("access_token", "refresh_token", "id_token"), machine["access_token"]]
    expect(credentials.compact.size).to eq(13)
    expect(AuditEvent.distinct.pluck(:event)).to include(
      "client.created", "client.secret_rotated", "user.signed_in", "user.sign_in_failed", "user.signed_out",
      "consent.granted", "token.issued", "token.revoked", "user.password_changed", "tokens.revoked_for_user"
    )
    log = AuditEvent.all.map(&:attributes).to_json
    credentials.compact.each { |credential| expect(log).not_to include(credential) }
  end
end
