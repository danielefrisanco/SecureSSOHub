require "rails_helper"

RSpec.describe "JWKS and token signatures", type: :request do
  let(:keys) { OAuth::SigningKey.for(realm: :default) }

  shared_examples "the JWKS document" do |path|
    it "serves the published keys at #{path} with cache headers and an ETag" do
      get path
      expect(response).to have_http_status(:ok)
      expect(response.media_type).to eq("application/json")
      expect(response.headers["cache-control"]).to include("public", "max-age=300")
      expect(response.headers["etag"]).to be_present

      document = response.parsed_body
      expect(document["keys"].pluck("kid")).to eq(keys.kids)
      expect(document["keys"].first).to include("kty" => "RSA", "use" => "sig", "alg" => "RS256", "kid" => keys.kid)
      expect(document["keys"].first.keys).to contain_exactly("kty", "n", "e", "kid", "use", "alg")
    end

    it "answers 304 to a matching If-None-Match at #{path}" do
      get path
      etag = response.headers["etag"]
      get path, headers: { "If-None-Match" => etag }
      expect(response).to have_http_status(:not_modified)
    end
  end

  include_examples "the JWKS document", "/.well-known/jwks.json"
  include_examples "the JWKS document", "/oauth/discovery/keys"

  it "is the jwks_uri the discovery document advertises" do
    get "/.well-known/openid-configuration"
    expect(response.parsed_body["jwks_uri"]).to end_with("/oauth/discovery/keys")
  end

  it "publishes the previous key during a rotation" do
    previous = OpenSSL::PKey::RSA.new(2048)
    rotated = OAuth::SigningKey.new([keys.private_key.to_pem, previous.to_pem])
    allow(OAuth::SigningKey).to receive(:for).and_return(rotated)

    get "/.well-known/jwks.json"
    kids = response.parsed_body["keys"].pluck("kid")
    expect(kids.length).to eq(2)
    expect(kids.first).to eq(keys.kid)
  end

  describe "an issued access token" do
    let(:user) { create(:user) }
    let(:application) do
      Doorkeeper::Application.create!(name: "spec", redirect_uri: "https://client.test/cb", scopes: "openid")
    end
    let!(:access_token) do
      Doorkeeper::AccessToken.create!(application: application, resource_owner_id: user.id, scopes: "openid",
                                      expires_in: 600)
    end

    it "is an RS256 JWT with the active kid that verifies against the JWKS" do
      token = access_token.plaintext_token
      get "/.well-known/jwks.json"
      jwks = JWT::JWK::Set.new(response.parsed_body)

      payload, header = JWT.decode(token, nil, true, algorithms: ["RS256"], jwks: jwks)
      expect(header).to include("alg" => "RS256", "kid" => keys.kid)
      expect(payload).to include("sub" => user.sso_id)
      expect(payload["exp"]).to be_within(5).of(Time.now.to_i + 600)
    end

    it "does not verify with an unrelated key" do
      stranger = OpenSSL::PKey::RSA.new(2048)
      expect { JWT.decode(access_token.plaintext_token, stranger.public_key, true, algorithms: ["RS256"]) }
        .to raise_error(JWT::VerificationError)
    end
  end
end
