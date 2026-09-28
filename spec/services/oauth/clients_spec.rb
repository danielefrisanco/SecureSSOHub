require "rails_helper"

RSpec.describe OAuth::Clients do
  let(:admin) { create(:user, :admin) }
  let(:member) { create(:user) }
  let(:base) do
    { name: "Dashboard", redirect_uris: ["https://dash.example.com/cb"], client_type: :confidential,
      scopes: %w[openid profile] }
  end

  def record(uid)
    Doorkeeper::Application.find_by!(uid: uid)
  end

  describe ".create" do
    it "registers an approved confidential client and returns the one-time secret" do
      registration = described_class.create(**base, by: admin)
      client = registration.client

      expect(client).to be_a(described_class::Client)
      expect(client).to have_attributes(name: "Dashboard", redirect_uris: ["https://dash.example.com/cb"],
                                        scopes: %w[openid profile], client_type: "confidential",
                                        confidential: true, approval_state: "approved",
                                        registered_via: "admin", owner_id: admin.id)
      expect(registration.secret).to be_present
      expect(record(client.uid).secret).not_to eq(registration.secret)
      expect(record(client.uid).secret_matches?(registration.secret)).to be(true)
    end

    it "never returns the secret again" do
      uid = described_class.create(**base, by: admin).client.uid
      expect(described_class.find(uid).to_h).not_to have_key(:secret)
    end

    it "registers a public client without a secret" do
      registration = described_class.create(**base, client_type: :public, by: admin)
      expect(registration.secret).to be_nil
      expect(registration.client).to have_attributes(client_type: "public", confidential: false)
      expect(record(registration.client.uid).secret).to be_nil
    end

    it "stores RFC 7591 metadata and an explicit owner" do
      registration = described_class.create(**base, by: admin, owner: member,
                                                    metadata: { software_id: "dash", software_version: "1.2",
                                                                client_uri: "https://dash.example.com",
                                                                logo_uri: "https://dash.example.com/logo.png",
                                                                contacts: ["ops@example.com"], ignored: "x" })
      expect(registration.client).to have_attributes(owner_id: member.id, software_id: "dash",
                                                     software_version: "1.2",
                                                     client_uri: "https://dash.example.com",
                                                     logo_uri: "https://dash.example.com/logo.png",
                                                     contacts: ["ops@example.com"])
    end

    it "raises Invalid with the rule violations" do
      expect { described_class.create(**base, redirect_uris: ["http://dash.example.com/cb"], by: admin) }
        .to raise_error(described_class::Invalid, /insecure uri/)
    end

    it "is forbidden to non-admins and anonymous callers" do
      expect { described_class.create(**base, by: member) }.to raise_error(described_class::Forbidden)
      expect { described_class.create(**base, by: nil) }.to raise_error(described_class::Forbidden)
    end
  end

  describe ".register_dynamic" do
    let(:request) do
      { name: "Agent", redirect_uris: ["http://localhost:8765/cb"], client_type: :public, scopes: %w[openid email] }
    end

    it "creates a pending, ownerless dynamic client under the approval policy" do
      registration = described_class.register_dynamic(**request, policy: :approval)
      expect(registration.client).to have_attributes(approval_state: "pending", registered_via: "dynamic",
                                                     owner_id: nil, client_type: "public")
      expect(registration.secret).to be_nil
      expect(described_class.usable?(registration.client.uid)).to be(false)
    end

    it "creates an approved client under the open policy" do
      registration = described_class.register_dynamic(**request, policy: :open)
      expect(registration.client.approval_state).to eq("approved")
      expect(described_class.usable?(registration.client.uid)).to be(true)
    end

    it "returns a one-time secret for a confidential dynamic client" do
      registration = described_class.register_dynamic(**request, client_type: :confidential,
                                                                 redirect_uris: ["https://agent.example.com/cb"],
                                                                 policy: :approval)
      expect(registration.secret).to be_present
      expect(record(registration.client.uid).secret_matches?(registration.secret)).to be(true)
    end

    it "refuses admin and machine scopes" do
      expect { described_class.register_dynamic(**request, scopes: %w[openid admin:clients], policy: :approval) }
        .to raise_error(described_class::Invalid, /admin:clients/)
      expect { described_class.register_dynamic(**request, scopes: %w[introspect], policy: :approval) }
        .to raise_error(described_class::Invalid, /introspect/)
    end

    it "rejects an unknown policy" do
      expect { described_class.register_dynamic(**request, policy: :yolo) }.to raise_error(ArgumentError)
    end

    it "still applies the client rules" do
      expect do
        described_class.register_dynamic(**request, redirect_uris: ["https://a.example.com/#x"], policy: :approval)
      end.to raise_error(described_class::Invalid, /fragment present/)
    end
  end

  describe ".list and .find" do
    it "lists newest first and filters by state" do
      older = create(:oauth_client, :pending, created_at: 1.hour.ago)
      newer = create(:oauth_client)
      expect(described_class.list.map(&:uid)).to eq([newer.uid, older.uid])
      expect(described_class.list(state: :pending).map(&:uid)).to eq([older.uid])
    end

    it "finds by client_id and returns nil for strangers" do
      client = create(:oauth_client, :public)
      expect(described_class.find(client.uid)).to have_attributes(uid: client.uid, client_type: "public")
      expect(described_class.find("nope")).to be_nil
    end
  end

  describe ".usable?" do
    it "is true only for approved clients" do
      expect(described_class.usable?(create(:oauth_client).uid)).to be(true)
      expect(described_class.usable?(create(:oauth_client, :pending).uid)).to be(false)
      expect(described_class.usable?(create(:oauth_client, :revoked).uid)).to be(false)
      expect(described_class.usable?("nope")).to be(false)
    end
  end

  describe ".update" do
    let(:client) { create(:oauth_client) }

    it "changes name, redirect URIs, scopes and metadata" do
      updated = described_class.update(client.uid, by: admin, name: "Renamed",
                                                   redirect_uris: ["https://new.example.com/cb"], scopes: %w[openid],
                                                   metadata: { client_uri: "https://new.example.com" })
      expect(updated).to have_attributes(name: "Renamed", redirect_uris: ["https://new.example.com/cb"],
                                         scopes: %w[openid], client_uri: "https://new.example.com")
    end

    it "leaves omitted attributes alone" do
      updated = described_class.update(client.uid, by: admin, name: "Only the name")
      expect(updated).to have_attributes(name: "Only the name", redirect_uris: ["https://client.test/callback"],
                                         scopes: %w[openid profile])
    end

    it "raises Invalid, NotFound and Forbidden" do
      expect { described_class.update(client.uid, by: admin, scopes: %w[nope]) }
        .to raise_error(described_class::Invalid, /catalogue/)
      expect { described_class.update("missing", by: admin, name: "x") }.to raise_error(described_class::NotFound)
      expect { described_class.update(client.uid, by: member, name: "x") }.to raise_error(described_class::Forbidden)
    end
  end

  describe ".rotate_secret" do
    it "replaces the secret, returns the new one once and keeps issued tokens valid" do
      registration = described_class.create(**base, by: admin)
      uid = registration.client.uid
      token = Doorkeeper::AccessToken.create!(application: record(uid), scopes: "openid", expires_in: 600)

      rotated = described_class.rotate_secret(uid, by: admin)
      expect(rotated.secret).to be_present
      expect(rotated.secret).not_to eq(registration.secret)
      expect(record(uid).secret_matches?(registration.secret)).to be(false)
      expect(record(uid).secret_matches?(rotated.secret)).to be(true)
      expect(token.reload.revoked_at).to be_nil
    end

    it "refuses for public clients and non-admins" do
      public_client = create(:oauth_client, :public)
      expect { described_class.rotate_secret(public_client.uid, by: admin) }
        .to raise_error(described_class::Invalid, /public client/)
      expect { described_class.rotate_secret(create(:oauth_client).uid, by: member) }
        .to raise_error(described_class::Forbidden)
    end
  end

  describe ".approve" do
    it "moves a pending client to approved" do
      client = create(:oauth_client, :pending)
      expect(described_class.approve(client.uid, by: admin).approval_state).to eq("approved")
      expect(described_class.usable?(client.uid)).to be(true)
    end

    it "refuses to approve a revoked client, and non-admins" do
      revoked = create(:oauth_client, :revoked)
      expect { described_class.approve(revoked.uid, by: admin) }
        .to raise_error(described_class::InvalidTransition, /revoked/)
      expect { described_class.approve(create(:oauth_client, :pending).uid, by: member) }
        .to raise_error(described_class::Forbidden)
    end
  end

  describe ".revoke" do
    let(:user) { create(:user) }
    let(:client) { create(:oauth_client) }

    it "revokes the client and every token and grant it holds" do
      token = Doorkeeper::AccessToken.create!(application: client, resource_owner_id: user.id, scopes: "openid",
                                              expires_in: 600)
      grant = Doorkeeper::AccessGrant.create!(application: client, resource_owner_id: user.id, scopes: "openid",
                                              expires_in: 60, redirect_uri: "https://client.test/callback")
      other = Doorkeeper::AccessToken.create!(application: create(:oauth_client), resource_owner_id: user.id,
                                              scopes: "openid", expires_in: 600)

      expect(described_class.revoke(client.uid, by: admin).approval_state).to eq("revoked")
      expect(token.reload).to be_revoked
      expect(grant.reload).to be_revoked
      expect(other.reload).not_to be_revoked
      expect(described_class.usable?(client.uid)).to be(false)
    end

    it "works from pending, is final, and needs an admin" do
      pending = create(:oauth_client, :pending)
      described_class.revoke(pending.uid, by: admin)
      expect { described_class.revoke(pending.uid, by: admin) }.to raise_error(described_class::InvalidTransition)
      expect { described_class.revoke(client.uid, by: member) }.to raise_error(described_class::Forbidden)
    end
  end
end
