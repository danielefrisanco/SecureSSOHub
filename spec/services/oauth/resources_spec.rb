require "rails_helper"

RSpec.describe OAuth::Resources do
  let(:issuer) { ENV.fetch("HUB_ISSUER") }

  it "roots the hub's resources at the issuer" do
    expect(described_class.issuer).to eq(issuer)
    expect(described_class.known).to eq(["#{issuer}/api", "#{issuer}/mcp"])
  end

  describe ".known?" do
    it "accepts the hub API and MCP resources" do
      expect(described_class.known?("#{issuer}/api")).to be(true)
      expect(described_class.known?("#{issuer}/mcp", client_uid: "any")).to be(true)
    end

    it "rejects unknown, relative, fragmented, malformed and blank values" do
      expect(described_class.known?("https://other.test/api")).to be(false)
      expect(described_class.known?("api")).to be(false)
      expect(described_class.known?("/api")).to be(false)
      expect(described_class.known?("#{issuer}/api#x")).to be(false)
      expect(described_class.known?("#{issuer}/api/")).to be(false)
      expect(described_class.known?("http://[bad")).to be(false)
      expect(described_class.known?("")).to be(false)
      expect(described_class.known?(nil)).to be(false)
    end
  end
end
