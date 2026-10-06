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

  it "enables trackable, lockable, timeoutable and confirmable" do
    expect(described_class.devise_modules).to include(:trackable, :lockable, :timeoutable, :confirmable)
  end
end

RSpec.describe User, "password rules", type: :model do
  let(:password) { "a long but famous passphrase" }
  let(:digest) { Digest::SHA1.hexdigest(password).upcase }
  let(:range_request) { a_request(:get, "https://api.pwnedpasswords.com/range/#{digest[0, 5]}") }

  around do |example|
    mode = Rails.configuration.x.password_breach_check
    example.run
  ensure
    Rails.configuration.x.password_breach_check = mode
  end

  def breach_check(mode)
    Rails.configuration.x.password_breach_check = mode
  end

  def stub_range(body)
    stub_request(:get, "https://api.pwnedpasswords.com/range/#{digest[0, 5]}").to_return(body: body)
  end

  def errors_for(candidate)
    user = build(:user, password: candidate)
    user.validate
    user.errors[:password]
  end

  it "needs at least 12 characters" do
    expect(errors_for("a" * 11)).to include("is too short (minimum is 12 characters)")
    expect(errors_for("abcdefghijkl")).to be_empty
  end

  it "refuses a password found in a known breach" do
    stub_range("#{digest[5..]}:42")
    expect(errors_for(password))
      .to contain_exactly("has appeared in a data breach, so attackers try it first. Please choose a different one.")
  end

  it "asks nothing about a password that is too short already" do
    errors_for("short")
    expect(a_request(:get, /pwnedpasswords/)).not_to have_been_made
  end

  it "asks nothing when the password does not change, though Devise keeps it on the record" do
    user = create(:user, password: password)
    WebMock.reset_executed_requests!
    user.update!(name: "Renamed")

    expect(range_request).not_to have_been_made
  end

  it "accepts the password and logs a warning when the API cannot be reached, by default (warn)" do
    breach_check(:warn)
    stub_request(:get, /pwnedpasswords/).to_timeout
    allow(Rails.logger).to receive(:warn)

    expect(errors_for(password)).to be_empty
    expect(Rails.logger).to have_received(:warn).with(/Breached-password check unavailable .*accepted unchecked/)
  end

  it "refuses the password when the API cannot be reached and the mode is block" do
    breach_check(:block)
    stub_request(:get, /pwnedpasswords/).to_return(status: 500)

    expect(errors_for(password)).to contain_exactly(
      "could not be checked against known data breaches right now. Please try again in a few minutes."
    )
  end

  it "checks nothing when the mode is off" do
    breach_check(:off)
    stub_range("#{digest[5..]}:42")

    expect(errors_for(password)).to be_empty
    expect(range_request).not_to have_been_made
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
