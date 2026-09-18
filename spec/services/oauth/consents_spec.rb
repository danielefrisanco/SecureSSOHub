require "rails_helper"

RSpec.describe OAuth::Consents do
  let(:user) { create(:user) }
  let(:client) { create(:oauth_client, scopes: "openid profile email") }

  describe ".covers?" do
    it "is false before any consent" do
      expect(described_class.covers?(user: user, client_uid: client.uid, scopes: %w[openid])).to be(false)
      expect(described_class.granted_scopes(user: user, client_uid: client.uid)).to eq([])
    end

    it "is true for the consented scopes and any subset, false for a superset" do
      described_class.grant(user: user, client_uid: client.uid, scopes: %w[openid profile])

      expect(described_class.covers?(user: user, client_uid: client.uid, scopes: %w[openid profile])).to be(true)
      expect(described_class.covers?(user: user, client_uid: client.uid, scopes: %w[profile])).to be(true)
      expect(described_class.covers?(user: user, client_uid: client.uid, scopes: [])).to be(true)
      expect(described_class.covers?(user: user, client_uid: client.uid, scopes: %w[openid email])).to be(false)
    end

    it "keeps consents apart per user and per client" do
      described_class.grant(user: user, client_uid: client.uid, scopes: %w[openid])

      expect(described_class.covers?(user: create(:user), client_uid: client.uid, scopes: %w[openid])).to be(false)
      other = create(:oauth_client)
      expect(described_class.covers?(user: user, client_uid: other.uid, scopes: %w[openid])).to be(false)
      expect(described_class.covers?(user: user, client_uid: "nope", scopes: %w[openid])).to be(false)
    end
  end

  describe ".grant" do
    it "persists one live consent row and returns it" do
      consent = described_class.grant(user: user, client_uid: client.uid, scopes: %w[openid profile])

      expect(consent).to have_attributes(client_uid: client.uid, subject_id: user.id, scopes: %w[openid profile],
                                         revoked_at: nil)
      expect(consent.granted_at).to be_within(2.seconds).of(Time.current)
      expect(OAuthConsent.live.where(user: user).count).to eq(1)
    end

    it "merges scopes into the existing consent instead of adding a row" do
      described_class.grant(user: user, client_uid: client.uid, scopes: %w[openid])
      consent = described_class.grant(user: user, client_uid: client.uid, scopes: %w[profile openid])

      expect(consent.scopes).to eq(%w[openid profile])
      expect(OAuthConsent.where(user: user).count).to eq(1)
      expect(described_class.for(user: user).map(&:scopes)).to eq([%w[openid profile]])
    end

    it "refuses an unknown client" do
      expect { described_class.grant(user: user, client_uid: "nope", scopes: %w[openid]) }
        .to raise_error(OAuth::Clients::NotFound)
    end
  end

  describe ".revoke" do
    it "closes the consent, keeps the row for history and revokes the client's tokens for that user" do
      described_class.grant(user: user, client_uid: client.uid, scopes: %w[openid])
      token = Doorkeeper::AccessToken.create!(application: client, resource_owner_id: user.id, scopes: "openid",
                                              expires_in: 600)

      consent = described_class.revoke(user: user, client_uid: client.uid)

      expect(consent.revoked_at).to be_present
      expect(described_class.covers?(user: user, client_uid: client.uid, scopes: %w[openid])).to be(false)
      expect(described_class.for(user: user)).to eq([])
      expect(OAuthConsent.where(user: user).count).to eq(1)
      expect(token.reload.revoked_at).to be_present
    end

    it "returns nil when there is nothing to revoke" do
      expect(described_class.revoke(user: user, client_uid: client.uid)).to be_nil
    end

    it "lets the user consent again afterwards" do
      described_class.grant(user: user, client_uid: client.uid, scopes: %w[openid])
      described_class.revoke(user: user, client_uid: client.uid)
      described_class.grant(user: user, client_uid: client.uid, scopes: %w[profile])

      expect(described_class.granted_scopes(user: user, client_uid: client.uid)).to eq(%w[profile])
      expect(OAuthConsent.where(user: user).count).to eq(2)
    end
  end

  describe ".for" do
    it "lists the user's live consents, newest first" do
      other = create(:oauth_client)
      described_class.grant(user: user, client_uid: client.uid, scopes: %w[openid])
      Timecop.travel(1.minute.from_now) { described_class.grant(user: user, client_uid: other.uid, scopes: %w[openid]) }
      described_class.grant(user: create(:user), client_uid: client.uid, scopes: %w[openid])

      expect(described_class.for(user: user).map(&:client_uid)).to eq([other.uid, client.uid])
    end
  end
end
