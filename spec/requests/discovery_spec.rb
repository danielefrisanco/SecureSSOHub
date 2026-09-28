require "rails_helper"

# The two well-known metadata documents (OpenID Connect Discovery and
# RFC 8414), both rendered from OAuth::Metadata by WellKnownController.
RSpec.describe "Discovery documents", type: :request do
  let(:issuer) { ENV.fetch("HUB_ISSUER") }

  # Endpoint URLs are asserted literally: if a Doorkeeper-mounted route moves,
  # this fails and the advertised document is reviewed on purpose.
  let(:oauth_fields) do
    {
      "issuer" => issuer,
      "authorization_endpoint" => "#{issuer}/oauth/authorize",
      "token_endpoint" => "#{issuer}/oauth/token",
      "revocation_endpoint" => "#{issuer}/oauth/revoke",
      "introspection_endpoint" => "#{issuer}/oauth/introspect",
      "jwks_uri" => "#{issuer}/.well-known/jwks.json",
      "scopes_supported" => OAuth::Scopes.names,
      "response_types_supported" => ["code"],
      "grant_types_supported" => %w[authorization_code client_credentials refresh_token],
      "code_challenge_methods_supported" => ["S256"],
      "token_endpoint_auth_methods_supported" => %w[client_secret_basic client_secret_post none],
      "service_documentation" => "https://github.com/danielefrisanco/SecureSSOHub#readme"
    }
  end

  let(:oidc_fields) do
    {
      "userinfo_endpoint" => "#{issuer}/oauth/userinfo",
      "id_token_signing_alg_values_supported" => ["RS256"],
      "subject_types_supported" => ["public"],
      "claims_supported" => %w[sub iss aud exp iat auth_time nonce name email email_verified admin]
    }
  end

  shared_examples "a public metadata document" do |path|
    it "is JSON, public for five minutes and revalidates with an ETag" do
      get path
      expect(response).to have_http_status(:ok)
      expect(response.media_type).to eq("application/json")
      expect(response.headers["cache-control"]).to include("public", "max-age=300")
      expect(response.headers["etag"]).to be_present

      get path, headers: { "If-None-Match" => response.headers["etag"] }
      expect(response).to have_http_status(:not_modified)
    end

    it "builds every URL from HUB_ISSUER, not from the request Host" do
      get path, headers: { "Host" => "evil.example", "X-Forwarded-Host" => "evil.example" }
      urls = response.parsed_body.select { |key, _| key.end_with?("_endpoint", "_uri", "issuer") }.values
      expect(urls).not_to be_empty
      expect(urls).to all(start_with(issuer))
    end

    it "allows a cross-origin GET" do
      get path, headers: { "Origin" => "https://spa.example" }
      expect(response.headers["access-control-allow-origin"]).to eq("*")
    end

    it "answers a CORS preflight" do
      options path, headers: { "Origin" => "https://spa.example", "Access-Control-Request-Method" => "GET" }
      expect(response).to have_http_status(:ok)
      expect(response.headers["access-control-allow-origin"]).to eq("*")
      expect(response.headers["access-control-allow-methods"]).to include("GET")
    end
  end

  describe "GET /.well-known/openid-configuration" do
    include_examples "a public metadata document", "/.well-known/openid-configuration"

    it "carries the OAuth and the OpenID Connect fields" do
      get "/.well-known/openid-configuration"
      expect(response.parsed_body).to eq(oauth_fields.merge(oidc_fields))
    end
  end

  describe "GET /.well-known/oauth-authorization-server" do
    include_examples "a public metadata document", "/.well-known/oauth-authorization-server"

    it "carries the OAuth fields only" do
      get "/.well-known/oauth-authorization-server"
      expect(response.parsed_body).to eq(oauth_fields)
    end
  end

  it "keeps scopes_supported in step with the catalogue" do
    allow(OAuth::Scopes).to receive(:names).and_return(%w[openid custom])
    get "/.well-known/oauth-authorization-server"
    expect(response.parsed_body["scopes_supported"]).to eq(%w[openid custom])
  end

  it "does not advertise dynamic registration yet" do
    get "/.well-known/openid-configuration"
    expect(response.parsed_body).not_to have_key("registration_endpoint")
  end

  describe "CORS scope" do
    it "is also open on the JWKS" do
      get "/.well-known/jwks.json", headers: { "Origin" => "https://spa.example" }
      expect(response.headers["access-control-allow-origin"]).to eq("*")
    end

    it "does not reach the token endpoint" do
      post "/oauth/token", headers: { "Origin" => "https://spa.example" }
      expect(response.headers).not_to have_key("access-control-allow-origin")

      options "/oauth/token", headers: { "Origin" => "https://spa.example", "Access-Control-Request-Method" => "POST" }
      expect(response.headers).not_to have_key("access-control-allow-origin")
    end
  end
end
