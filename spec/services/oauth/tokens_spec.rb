require "rails_helper"

RSpec.describe OAuth::Tokens do
  let(:user) { create(:user) }
  let(:client) { create(:oauth_client) }

  def token_for(user, client, **attributes)
    Doorkeeper::AccessToken.create!(application: client, resource_owner_id: user.id, scopes: "openid", expires_in: 600,
                                    **attributes)
  end

  def grant_for(user, client)
    Doorkeeper::AccessGrant.create!(application: client, resource_owner_id: user.id, scopes: "openid", expires_in: 60,
                                    redirect_uri: client.redirect_uri)
  end

  describe ".active?" do
    it "is true only for a stored, unrevoked token with that jti" do
      token = token_for(user, client)
      expect(token.jti).to match(/\A\h{8}-\h{4}-\h{4}-\h{4}-\h{12}\z/)
      expect(described_class.active?(jti: token.jti)).to be(true)
      expect(described_class.active?(jti: "unknown")).to be(false)
      expect(described_class.active?(jti: nil)).to be(false)

      token.revoke
      expect(described_class.active?(jti: token.jti)).to be(false)
    end

    it "exposes the same jti on the wrapped token" do
      token = token_for(user, client)
      expect(described_class.active_for(user: user).map(&:jti)).to eq([token.jti])
    end
  end

  describe ".revoke_for" do
    it "revokes only the tokens and codes the client holds for that user" do
      mine = token_for(user, client)
      my_grant = grant_for(user, client)
      other_user = token_for(create(:user), client)
      other_client = token_for(user, create(:oauth_client))

      expect(described_class.revoke_for(user: user, client_uid: client.uid)).to eq(1)

      expect(mine.reload.revoked_at).to be_present
      expect(my_grant.reload.revoked_at).to be_present
      expect(other_user.reload.revoked_at).to be_nil
      expect(other_client.reload.revoked_at).to be_nil
      expect(described_class.active_for(user: user).map(&:client_uid)).to eq([other_client.application.uid])
    end

    it "returns 0 for an unknown client or nothing to revoke" do
      expect(described_class.revoke_for(user: user, client_uid: "nope")).to eq(0)
      expect(described_class.revoke_for(user: user, client_uid: client.uid)).to eq(0)
    end
  end

  describe ".active_for" do
    it "lists live tokens newest first with the client's uid and name" do
      older = token_for(user, client, created_at: 2.minutes.ago)
      newer = token_for(user, create(:oauth_client, name: "Notes"))

      listed = described_class.active_for(user: user)
      expect(listed.map(&:jti)).to eq([newer.jti, older.jti])
      expect(listed.first).to have_attributes(client_uid: newer.application.uid, client_name: "Notes",
                                              scopes: ["openid"], refresh_expires_at: nil)
    end

    it "leaves out revoked tokens, other users' tokens and expired tokens without a refresh token" do
      token_for(user, client).revoke
      token_for(create(:user), client)
      token_for(user, client, created_at: 1.hour.ago)

      expect(described_class.active_for(user: user)).to be_empty
    end

    it "keeps an expired access token whose refresh token is still within its lifetime" do
      grant = grant_for(user, client)
      token = token_for(user, client, created_at: 1.hour.ago, use_refresh_token: true, access_grant_id: grant.id)

      listed = described_class.active_for(user: user)
      expect(listed.map(&:jti)).to eq([token.jti])
      expect(listed.first.refresh_expires_at)
        .to be_within(1.second).of(grant.created_at + described_class.refresh_token_ttl)

      Timecop.travel(described_class.refresh_token_ttl.from_now + 1.minute) do
        expect(described_class.active_for(user: user)).to be_empty
      end
    end
  end

  describe ".revoke" do
    let(:other) { create(:user) }

    it "revokes the owner's token found by jti, access token or refresh token" do
      by_jti = token_for(user, client)
      by_jwt = token_for(user, client)
      by_refresh = token_for(user, client, use_refresh_token: true)

      expect(described_class.revoke(by_jti.jti, by: user)).to eq(1)
      expect(described_class.revoke(by_jwt.plaintext_token, by: user)).to eq(1)
      expect(described_class.revoke(by_refresh.plaintext_refresh_token, by: user)).to eq(1)
      expect([by_jti, by_jwt, by_refresh].map { |token| token.reload.revoked? }).to all(be(true))
    end

    it "revokes the token's whole family, and nothing outside it" do
      grant = grant_for(user, client)
      rotated = token_for(user, client, use_refresh_token: true, access_grant_id: grant.id)
      sibling = token_for(user, client, access_grant_id: grant.id)
      unrelated = token_for(user, client)

      expect(described_class.revoke(rotated.plaintext_refresh_token, by: user)).to eq(2)
      expect(rotated.reload.revoked?).to be(true)
      expect(sibling.reload.revoked?).to be(true)
      expect(unrelated.reload.revoked?).to be(false)
    end

    it "lets an administrator revoke anyone's token but not another user" do
      token = token_for(user, client)

      expect(described_class.revoke(token.jti, by: other)).to eq(0)
      expect(token.reload.revoked?).to be(false)

      expect(described_class.revoke(token.jti, by: create(:user, :admin))).to eq(1)
      expect(token.reload.revoked?).to be(true)
    end

    it "revokes nothing for an unknown, blank or already revoked token" do
      token = token_for(user, client)
      token.revoke

      expect(described_class.revoke("unknown", by: user)).to eq(0)
      expect(described_class.revoke("", by: user)).to eq(0)
      expect(described_class.revoke(nil, by: user)).to eq(0)
      expect(described_class.revoke(token.jti, by: user)).to eq(0)
    end
  end

  describe ".revoke_all_for" do
    it "revokes every token and pending code of the user across clients, and nobody else's" do
      mine = [token_for(user, client), token_for(user, create(:oauth_client), use_refresh_token: true)]
      my_grant = grant_for(user, client)
      theirs = token_for(create(:user), client)

      expect(described_class.revoke_all_for(user: user)).to eq(2)
      expect(mine.map { |token| token.reload.revoked? }).to all(be(true))
      expect(my_grant.reload.revoked?).to be(true)
      expect(theirs.reload.revoked?).to be(false)
      expect(described_class.active_for(user: user)).to be_empty
    end
  end

  describe ".revoke_all" do
    it "revokes every token and code of the client, for every user, and leaves other clients alone" do
      mine = [token_for(user, client), token_for(create(:user), client)]
      grant = grant_for(user, client)
      elsewhere = token_for(user, create(:oauth_client))

      expect(described_class.revoke_all(client_uid: client.uid)).to eq(2)
      expect(mine.map { |token| token.reload.revoked? }).to all(be(true))
      expect(grant.reload.revoked?).to be(true)
      expect(elsewhere.reload.revoked?).to be(false)
      expect(described_class.revoke_all(client_uid: "nope")).to eq(0)
    end
  end
end
