require "rails_helper"

# config/oauth_scopes.yml is the single scope catalogue: Doorkeeper's
# default/optional scopes, the consent page and userinfo all read it through
# OAuth::Scopes, so every entry must be complete.
RSpec.describe OAuth::Scopes do
  it "lists the catalogue from config/oauth_scopes.yml" do
    expect(described_class.names).to contain_exactly(
      "openid", "profile", "email", "offline_access", "introspect",
      "admin:clients", "admin:users", "admin:tokens", "admin:audit"
    )
  end

  it "gives every scope a user-facing description" do
    described_class.names.each do |name|
      expect(described_class.description(name)).to be_present, "#{name} has no description"
    end
  end

  it "describes a scope and returns nil for one outside the catalogue" do
    expect(described_class.description("email")).to eq("See your email address")
    expect(described_class.description(:openid)).to eq("Sign you in")
    expect(described_class.description("bogus")).to be_nil
    expect(described_class.known?("bogus")).to be(false)
    expect(described_class.known?("profile")).to be(true)
  end

  it "flags the default, admin and machine scopes" do
    expect(described_class.names.select { |name| described_class.default?(name) }).to eq(["openid"])
    expect(described_class.admin_names).to contain_exactly("admin:clients", "admin:users", "admin:tokens",
                                                           "admin:audit")
    expect(described_class.names.select { |name| described_class.admin?(name) }).to eq(described_class.admin_names)
    expect(described_class.names.select { |name| described_class.machine?(name) }).to eq(["introspect"])
    expect(described_class.admin?("bogus")).to be(false)
  end

  it "keeps admin and machine scopes away from dynamically registered clients" do
    expect(described_class.dynamic_registration_names).to eq(%w[openid profile email offline_access])
  end
end
