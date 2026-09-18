require "rails_helper"

RSpec.describe OAuth::SigningKey do
  let(:rsa) { OpenSSL::PKey::RSA.new(2048) }
  let(:other_rsa) { OpenSSL::PKey::RSA.new(2048) }

  # RFC 7638: base64url(SHA-256(canonical JSON of the public JWK members)).
  def thumbprint(key)
    jwk = { e: Base64.urlsafe_encode64(key.e.to_s(2), padding: false),
            kty: "RSA",
            n: Base64.urlsafe_encode64(key.n.to_s(2), padding: false) }
    Base64.urlsafe_encode64(Digest::SHA256.digest(JSON.generate(jwk)), padding: false)
  end

  describe ".parse" do
    it "accepts a PEM" do
      expect(described_class.parse(rsa.to_pem).to_pem).to eq(rsa.to_pem)
    end

    it "accepts a base64-encoded PEM (single line, env-file friendly)" do
      encoded = Base64.strict_encode64(rsa.to_pem)
      expect(encoded).not_to include("\n")
      expect(described_class.parse(encoded).to_pem).to eq(rsa.to_pem)
    end

    it "rejects a key shorter than 2048 bits" do
      expect { described_class.parse(OpenSSL::PKey::RSA.new(1024).to_pem) }
        .to raise_error(described_class::Error, /at least 2048 bits/)
    end

    it "rejects a public key" do
      expect { described_class.parse(rsa.public_key.to_pem) }
        .to raise_error(described_class::Error, /private key/)
    end

    it "rejects garbage" do
      expect { described_class.parse("not a key") }.to raise_error(described_class::Error, /not a valid/)
    end
  end

  describe "#kid" do
    it "is the RFC 7638 thumbprint of the active public key" do
      keys = described_class.new([rsa.to_pem, nil])
      expect(keys.kid).to eq(thumbprint(rsa))
    end
  end

  describe "#jwks" do
    it "publishes only the active key when there is no previous key" do
      keys = described_class.new([rsa.to_pem])
      expect(keys.jwks[:keys].length).to eq(1)
      expect(keys.jwks[:keys].first).to include(kty: "RSA", use: "sig", alg: "RS256", kid: thumbprint(rsa))
      expect(keys.jwks[:keys].first.keys).not_to include(:d, :p, :q)
    end

    it "publishes the previous key after the active one during a rotation" do
      keys = described_class.new([rsa.to_pem, other_rsa.to_pem])
      expect(keys.kids).to eq([thumbprint(rsa), thumbprint(other_rsa)])
      expect(keys.pems).to eq([rsa.to_pem, other_rsa.to_pem])
      expect(keys.kid).to eq(thumbprint(rsa))
    end
  end

  describe ".for" do
    it "memoises the default realm and rejects others" do
      described_class.reset!
      first = described_class.for(realm: :default)
      expect(described_class.for(realm: :default)).to be(first)
      expect { described_class.for(realm: :other) }.to raise_error(described_class::Error, /unknown realm/)
    end

    it "requires a configured key" do
      expect { described_class.new([]) }.to raise_error(described_class::Error, /no signing key/)
    end
  end
end
