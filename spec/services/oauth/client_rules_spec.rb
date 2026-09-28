require "rails_helper"

RSpec.describe OAuth::ClientRules do
  def errors_for(client)
    client.validate
    client.errors.full_messages
  end

  describe "client type and secret consistency" do
    it "accepts the factory defaults for confidential and public clients" do
      expect(build(:oauth_client)).to be_valid
      expect(build(:oauth_client, :public)).to be_valid
    end

    it "rejects an unknown client type" do
      expect(errors_for(build(:oauth_client, client_type: "hybrid"))).to include(/Client type is not included/)
    end

    it "rejects a confidential flag that disagrees with the client type" do
      client = build(:oauth_client, client_type: "public", confidential: true)
      expect(errors_for(client)).to include("Confidential must be false for a public client")
    end

    it "rejects a public client that carries a secret" do
      client = build(:oauth_client, :public, secret: "should-not-be-here")
      expect(errors_for(client)).to include("Secret must be empty for a public client")
    end

    it "requires a secret for a confidential client (Doorkeeper generates one)" do
      client = create(:oauth_client)
      expect(client.secret).to be_present
      client.secret = nil
      expect(errors_for(client)).to include("Secret can't be blank")
    end

    it "stores no secret for a public client" do
      expect(create(:oauth_client, :public).secret).to be_nil
    end
  end

  describe "redirect URI allow-list" do
    {
      "https://app.example.com/callback" => nil,
      "https://app.example.com/cb?state=x" => nil,
      "http://localhost:8080/callback" => nil,
      "http://127.0.0.1/callback" => nil,
      "http://[::1]:3000/cb" => nil,
      "http://app.example.com/callback" => :insecure_uri,
      "https:///callback" => :missing_host,
      "https://user:pw@app.example.com/cb" => :userinfo_present,
      "https://app.example.com/cb#frag" => :fragment_present,
      "/relative/path" => :relative_uri,
      "urn:ietf:wg:oauth:2.0:oob" => :oob_uri,
      "com.example.app:opaque" => :opaque_uri,
      "not a uri" => :invalid_uri
    }.each do |uri, problem|
      it "#{problem ? "refuses (#{problem})" : 'accepts'} #{uri} for a confidential client" do
        expect(described_class.redirect_uri_problem(uri, public_client: false)).to eq(problem)
      end
    end

    it "allows a private-use scheme only for public clients" do
      uri = "com.example.app:/oauth2/callback"
      expect(described_class.redirect_uri_problem(uri, public_client: true)).to be_nil
      expect(described_class.redirect_uri_problem(uri, public_client: false))
        .to eq(:private_scheme_for_confidential_client)
    end

    it "checks every registered URI and names the offender" do
      client = build(:oauth_client, redirect_uri: ["https://ok.example.com/cb", "http://bad.example.com/cb"])
      expect(errors_for(client)).to include("Redirect URI http://bad.example.com/cb: insecure uri")
    end

    it "accepts a private-use scheme on a public client record" do
      expect(build(:oauth_client, :public, redirect_uri: "com.example.app:/callback")).to be_valid
    end
  end

  describe "scopes" do
    it "rejects a scope outside the catalogue" do
      client = build(:oauth_client, scopes: "openid launch_missiles")
      expect(errors_for(client)).to include("Scopes not in the catalogue: launch_missiles")
    end

    it "accepts an empty scope list (defaults apply at authorization)" do
      expect(build(:oauth_client, scopes: "")).to be_valid
    end
  end

  describe "approval state" do
    it "rejects an unknown state" do
      expect(errors_for(build(:oauth_client, approval_state: "maybe"))).to include(/Approval state is not included/)
    end

    {
      %w[pending approved] => true,
      %w[pending revoked] => true,
      %w[approved revoked] => true,
      %w[approved pending] => false,
      %w[revoked approved] => false,
      %w[revoked pending] => false
    }.each do |(from, to), allowed|
      it "#{allowed ? 'allows' : 'refuses'} #{from} → #{to}" do
        client = create(:oauth_client, approval_state: from)
        client.approval_state = to
        if allowed
          expect(client).to be_valid
        else
          expect(errors_for(client)).to include("Approval state cannot change from #{from} to #{to}")
        end
      end
    end
  end

  describe "registration source" do
    it "rejects an unknown source" do
      expect(errors_for(build(:oauth_client, registered_via: "carrier_pigeon")))
        .to include(/Registered via is not included/)
    end

    it "links the owner to a user" do
      owner = create(:user, :admin)
      expect(create(:oauth_client, owner: owner).reload.owner).to eq(owner)
    end
  end
end
