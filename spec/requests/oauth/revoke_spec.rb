require "rails_helper"
require "base64"
require "support/hub_access_token"

# POST /oauth/revoke — RFC 7009 (TASK-022): client authentication, ownership,
# token_type_hint as a hint, the refresh → access cascade, 200 for unknown
# tokens. Revocation is observed the way the hub's own API sees it
# (OAuth::Tokens.active? on the JWT's jti) and at the token endpoint.
RSpec.describe "OAuth token revocation", type: :request do
  include HubAccessToken

  let(:user) { create(:user) }
  let(:scopes) { "openid offline_access" }
  let(:public_client) { create(:oauth_client, :public, scopes: scopes) }
  let(:confidential_client) { create(:oauth_client, scopes: scopes) }

  def basic_auth(client)
    { "Authorization" => "Basic #{Base64.strict_encode64("#{client.uid}:#{client.plaintext_secret}")}" }
  end

  # A token response from the full authorization-code flow; a confidential
  # client authenticates at the token endpoint with client_secret_basic.
  def tokens_for(client)
    sign_in user
    post "/oauth/authorize", params: { client_id: client.uid, redirect_uri: client.redirect_uri, response_type: "code",
                                       scope: scopes, code_challenge: HubAccessToken::CODE_CHALLENGE,
                                       code_challenge_method: "S256" }
    sign_out user
    code = Rack::Utils.parse_query(URI.parse(response.location).query).fetch("code")
    post "/oauth/token", params: { grant_type: "authorization_code", client_id: client.uid, code: code,
                                   redirect_uri: client.redirect_uri, code_verifier: HubAccessToken::CODE_VERIFIER },
                         headers: client.confidential ? basic_auth(client) : {}
    response.parsed_body
  end

  def jti(access_token)
    JWT.decode(access_token, nil, false).first.fetch("jti")
  end

  def active?(access_token)
    OAuth::Tokens.active?(jti: jti(access_token))
  end

  def revoke(token, as:, hint: nil, headers: nil)
    params = { token: token, token_type_hint: hint }.compact
    params[:client_id] = as.uid unless headers
    post "/oauth/revoke", params: params, headers: headers || {}
  end

  def refresh(refresh_token, client)
    post "/oauth/token", params: { grant_type: "refresh_token", client_id: client.uid, refresh_token: refresh_token }
  end

  it "lets a confidential client revoke its access token with client_secret_basic" do
    access_token = tokens_for(confidential_client).fetch("access_token")

    revoke(access_token, as: confidential_client, headers: basic_auth(confidential_client))
    expect(response).to have_http_status(:ok)
    expect(response.parsed_body).to eq({})
    expect(active?(access_token)).to be(false)
  end

  it "lets a public client revoke its own token with its client_id alone" do
    access_token = tokens_for(public_client).fetch("access_token")

    revoke(access_token, as: public_client)
    expect(response).to have_http_status(:ok)
    expect(active?(access_token)).to be(false)
  end

  it "revokes a refresh token together with its access token" do
    body = tokens_for(public_client)

    revoke(body.fetch("refresh_token"), as: public_client, hint: "refresh_token")
    expect(response).to have_http_status(:ok)
    expect(active?(body.fetch("access_token"))).to be(false)

    refresh(body.fetch("refresh_token"), public_client)
    expect(response).to have_http_status(:bad_request)
    expect(response.parsed_body["error"]).to eq("invalid_grant")
  end

  it "revokes the refresh token issued with a revoked access token" do
    body = tokens_for(public_client)

    revoke(body.fetch("access_token"), as: public_client)
    refresh(body.fetch("refresh_token"), public_client)
    expect(response.parsed_body["error"]).to eq("invalid_grant")
  end

  it "treats token_type_hint as a hint: a wrong hint still finds the token" do
    access = tokens_for(public_client)
    refresh_only = tokens_for(public_client)

    revoke(access.fetch("access_token"), as: public_client, hint: "refresh_token")
    expect(response).to have_http_status(:ok)
    expect(active?(access.fetch("access_token"))).to be(false)

    revoke(refresh_only.fetch("refresh_token"), as: public_client, hint: "access_token")
    expect(response).to have_http_status(:ok)
    expect(active?(refresh_only.fetch("access_token"))).to be(false)
  end

  it "answers 200 for an unknown token" do
    revoke("not-a-token", as: public_client)
    expect(response).to have_http_status(:ok)

    revoke("not-a-token", as: confidential_client, headers: basic_auth(confidential_client))
    expect(response).to have_http_status(:ok)
  end

  it "refuses another client's token with 403 and leaves it active" do
    access_token = tokens_for(confidential_client).fetch("access_token")

    revoke(access_token, as: public_client)
    expect(response).to have_http_status(:forbidden)
    expect(response.parsed_body["error"]).to eq("unauthorized_client")
    expect(active?(access_token)).to be(true)

    other = create(:oauth_client, scopes: scopes)
    revoke(access_token, as: other, headers: basic_auth(other))
    expect(response).to have_http_status(:forbidden)
    expect(active?(access_token)).to be(true)
  end

  it "refuses a confidential client without its secret, or with a wrong one" do
    access_token = tokens_for(confidential_client).fetch("access_token")

    revoke(access_token, as: confidential_client)
    expect(response).to have_http_status(:forbidden)

    wrong = { "Authorization" => "Basic #{Base64.strict_encode64("#{confidential_client.uid}:wrong")}" }
    revoke(access_token, as: confidential_client, headers: wrong)
    expect(response).to have_http_status(:forbidden)
    expect(active?(access_token)).to be(true)
  end

  it "refuses a request without any client" do
    access_token = tokens_for(public_client).fetch("access_token")

    post "/oauth/revoke", params: { token: access_token }
    expect(response).to have_http_status(:forbidden)
    expect(active?(access_token)).to be(true)
  end
end
