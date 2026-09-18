require "rails_helper"

RSpec.describe OAuth::Tokens do
  let(:user) { create(:user) }
  let(:client) { create(:oauth_client) }

  def token_for(user, client)
    Doorkeeper::AccessToken.create!(application: client, resource_owner_id: user.id, scopes: "openid", expires_in: 600)
  end

  def grant_for(user, client)
    Doorkeeper::AccessGrant.create!(application: client, resource_owner_id: user.id, scopes: "openid", expires_in: 60,
                                    redirect_uri: client.redirect_uri)
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
end
