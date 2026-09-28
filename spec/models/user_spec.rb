require 'rails_helper'

RSpec.describe User, type: :model do
  it "is valid with an email and password" do
    expect(build(:user)).to be_valid
  end

  it "generates a UUID sso_id on create" do
    user = create(:user)
    expect(user.sso_id).to match(/\A\h{8}-\h{4}-\h{4}-\h{4}-\h{12}\z/)
  end

  it "rejects a duplicate sso_id" do
    existing = create(:user)
    duplicate = build(:user, sso_id: existing.sso_id)
    expect(duplicate).not_to be_valid
    expect(duplicate.errors[:sso_id]).to include("has already been taken")
  end

  it "authenticates with the stored password" do
    user = create(:user, password: "correct horse battery staple")
    expect(user.valid_password?("correct horse battery staple")).to be true
    expect(user.valid_password?("wrong")).to be false
  end

  it "does not expose registration" do
    expect(described_class.devise_modules).not_to include(:registerable)
  end

  it "enables trackable, lockable and timeoutable" do
    expect(described_class.devise_modules).to include(:trackable, :lockable, :timeoutable)
  end
end

RSpec.describe User, "sign out everywhere", type: :model do
  let(:user) { create(:user) }
  let(:clients) { create_list(:oauth_client, 2) }

  before do
    clients.each do |client|
      client.access_tokens.create!(resource_owner_id: user.id, scopes: "openid", expires_in: 600,
                                   use_refresh_token: true)
    end
    clients.first.access_grants.create!(resource_owner_id: user.id, scopes: "openid", expires_in: 60,
                                        redirect_uri: clients.first.redirect_uri)
  end

  def live_codes
    clients.first.access_grants.where(revoked_at: nil)
  end

  it "revokes every token and code of the user when the password is changed" do
    user.update!(password: "a brand new passphrase")
    expect(OAuth::Tokens.active_for(user: user)).to be_empty
    expect(live_codes).to be_empty
  end

  it "revokes every token when the password is reset" do
    user.reset_password("a brand new passphrase", "a brand new passphrase")
    expect(OAuth::Tokens.active_for(user: user)).to be_empty
  end

  it "revokes every token when an administrator disables the account" do
    user.update!(disabled_at: Time.current)
    expect(OAuth::Tokens.active_for(user: user)).to be_empty
    expect(live_codes).to be_empty
  end

  it "leaves other users' tokens alone" do
    other = create(:user)
    clients.first.access_tokens.create!(resource_owner_id: other.id, scopes: "openid", expires_in: 600)

    user.update!(disabled_at: Time.current)
    expect(OAuth::Tokens.active_for(user: other).size).to eq(1)
  end

  it "keeps tokens on a failed-attempts lock, sign-in tracking or a profile change" do
    user.lock_access!(send_instructions: false)
    user.update!(name: "Renamed", sign_in_count: 3, last_sign_in_at: Time.current)

    expect(OAuth::Tokens.active_for(user: user).size).to eq(2)
    expect(live_codes.size).to eq(1)
  end
end

RSpec.describe User, "factory", type: :model do
  it "builds an admin with the :admin trait" do
    expect(build(:user, :admin)).to be_valid.and have_attributes(is_admin: true)
  end
end
