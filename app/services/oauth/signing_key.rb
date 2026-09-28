require "jwt"
require "openssl"

module OAuth
  # The hub's token signing keys: the active key plus, during a rotation, the
  # previous one (still published so tokens it signed verify until they expire).
  #
  # Key material is loaded and validated at boot by config/initializers/doorkeeper.rb
  # (initializers cannot use autoloaded code) into Rails.configuration.x.oauth;
  # this class is the application's only way to reach it, and the only place
  # that knows there is a "current" and a "previous". Realm-ready: every caller
  # asks for a realm, and today there is one — see docs/ARCHITECTURE.md §6.
  class SigningKey
    ALGORITHM = "RS256".freeze
    MIN_BITS = 2048

    class Error < StandardError; end

    # @param realm [Symbol] the realm whose keys are wanted (only :default exists).
    # @return [SigningKey]
    def self.for(realm: :default)
      raise Error, "unknown realm #{realm.inspect}" unless realm == :default

      @instances ||= {}
      @instances[realm] ||= new(Rails.configuration.x.oauth.signing_key_pems)
    end

    # Forgets the memoised keys (tests, key reload).
    def self.reset!
      @instances = {}
    end

    # Parses a PEM, or a base64-encoded PEM (newlines are awkward in env files),
    # and refuses anything that is not an RSA private key of at least MIN_BITS.
    #
    # @param material [String]
    # @return [OpenSSL::PKey::RSA]
    def self.parse(material)
      text = material.to_s.strip
      text = Base64.strict_decode64(text) unless text.start_with?("-----BEGIN")
      key = OpenSSL::PKey::RSA.new(text)
      raise Error, "signing key must be an RSA private key" unless key.private?
      raise Error, "signing key must be at least #{MIN_BITS} bits (got #{key.n.num_bits})" if key.n.num_bits < MIN_BITS

      key
    rescue OpenSSL::PKey::PKeyError, ArgumentError => e
      raise Error, "signing key is not a valid PEM/base64 PEM RSA key: #{e.message}"
    end

    attr_reader :current, :previous

    # @param pems [Array<String>] [current_pem, previous_pem]; previous may be nil.
    def initialize(pems)
      current_pem, previous_pem = Array(pems)
      raise Error, "no signing key configured" if current_pem.blank?

      @current = self.class.parse(current_pem)
      @previous = previous_pem.presence && self.class.parse(previous_pem)
    end

    # RFC 7638 thumbprint of the active key — the `kid` every token carries.
    def kid
      jwk(current).kid
    end

    alias private_key current
    delegate :public_key, to: :current

    # PEMs in the order doorkeeper-openid_connect expects: active first.
    def pems
      [current, previous].compact.map(&:to_pem)
    end

    # The JWKS document: public parts of the active and previous keys.
    #
    # @return [Hash] { keys: [...] }
    def jwks
      { keys: [current, previous].compact.map { |key| jwk(key).export.merge(use: "sig", alg: ALGORITHM) } }
    end

    # @return [Array<String>] kids of every published key.
    def kids
      jwks[:keys].pluck(:kid)
    end

    private

    def jwk(key)
      JWT::JWK.new(key.public_key, kid_generator: ::JWT::JWK::Thumbprint)
    end
  end
end
