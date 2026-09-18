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

RSpec.describe User, "factory", type: :model do
  it "builds an admin with the :admin trait" do
    expect(build(:user, :admin)).to be_valid.and have_attributes(is_admin: true)
  end
end
