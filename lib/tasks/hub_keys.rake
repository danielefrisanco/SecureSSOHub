require "base64"
require "openssl"

# Operator tooling for the token signing keys (see README "Key rotation").
namespace :hub do
  namespace :keys do
    desc "Print a fresh RSA-2048 signing key in the OIDC_SIGNING_KEY format (never written to disk)"
    task generate: :environment do
      key = OpenSSL::PKey::RSA.new(2048)
      kid = JWT::JWK.new(key.public_key, kid_generator: JWT::JWK::Thumbprint).kid
      puts "# kid: #{kid}"
      puts "# Set as OIDC_SIGNING_KEY (base64 of the PEM, single line). To rotate: move the"
      puts "# current value to OIDC_SIGNING_KEY_PREVIOUS first, deploy, and drop PREVIOUS"
      puts "# once every token signed with it has expired."
      puts "OIDC_SIGNING_KEY=#{Base64.strict_encode64(key.to_pem)}"
    end

    desc "Show the kids of the signing keys the app currently loads (active first)"
    task show: :environment do
      keys = OAuth::SigningKey.for(realm: :default)
      puts "active:   #{keys.kid}"
      previous = keys.kids - [keys.kid]
      puts "previous: #{previous.first || '(none)'}"
    end
  end
end
