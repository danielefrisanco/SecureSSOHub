require "rails_helper"

# The claim set is asserted end to end in spec/requests/oauth/token_spec.rb;
# here: the inputs Doorkeeper hands the generator that the HTTP flow of this
# phase cannot produce yet (a client-only token, TASK-024).
RSpec.describe OAuth::TokenPayload do
  let(:client) { create(:oauth_client, scopes: "openid introspect") }
  let(:now) { Time.zone.parse("2026-09-18 12:00:00 UTC") }

  def build(**overrides)
    described_class.build({ application: client, scopes: Doorkeeper::OAuth::Scopes.from_string("introspect"),
                            expires_in: 600, created_at: now, resource: nil, resource_owner_id: nil,
                            jti: "0f5d6a4e-1111-4222-8333-444455556666" }.merge(overrides))
  end

  it "uses the client as subject and audience when there is no resource owner" do
    payload = build
    expect(payload.keys).to contain_exactly(:iss, :sub, :aud, :azp, :scope, :scopes, :jti, :iat, :nbf, :exp, :admin)
    expect(payload).to include(
      iss: "https://hub.test", sub: client.uid, aud: client.uid, azp: client.uid, scope: "introspect",
      scopes: ["introspect"], iat: now.to_i, nbf: now.to_i, exp: now.to_i + 600, admin: false
    )
    expect(payload[:jti]).to eq("0f5d6a4e-1111-4222-8333-444455556666")
  end

  it "takes the jti from the record rather than inventing one" do
    expect { described_class.build(application: client, scopes: [], expires_in: 600) }.to raise_error(KeyError)
  end

  it "prefers the resource indicator as audience" do
    expect(build(resource: OAuth::Resources.hub_api)).to include(aud: "https://hub.test/api", azp: client.uid)
  end

  it "never adds profile claims without a resource owner, whatever the scopes" do
    payload = build(scopes: Doorkeeper::OAuth::Scopes.from_string("profile email"))
    expect(payload.keys).not_to include(:name, :email, :email_verified)
  end

  it "publishes the active kid and the at+jwt type in the header" do
    expect(described_class.headers).to eq(kid: OAuth::SigningKey.for(realm: :default).kid, typ: "at+jwt")
  end
end
