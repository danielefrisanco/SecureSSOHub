require "securerandom"

module OAuth
  # The claims of an access token (RFC 9068 JWT profile), built for
  # doorkeeper-jwt from the attributes Doorkeeper hands its token generator
  # (config/initializers/doorkeeper.rb). Documented in docs/ARCHITECTURE.md §3.
  #
  #   iss        HUB_ISSUER
  #   sub        the user's sso_id; the client uid for client_credentials
  #   aud        the RFC 8707 resource of the grant, else the client uid
  #   azp        the client the token was issued to
  #   scope      space-delimited (OAuth); `scopes` array for rack-jwt-verifier
  #   jti        unique per token
  #   iat/nbf    issue time; exp = iat + Doorkeeper's access_token_expires_in
  #   name       with the `profile` scope
  #   email,
  #   email_verified  with the `email` scope
  #   admin      whether the user is an administrator (always present, boolean)
  #
  # Nothing else about the user is ever placed in a token.
  class TokenPayload
    TYPE = "at+jwt".freeze

    # @param attributes [Hash] Doorkeeper's token-generator attributes:
    #   :resource_owner_id, :application, :scopes, :expires_in, :created_at,
    #   :resource (custom attribute copied from the grant)
    # @return [Hash] the claims
    def self.build(attributes)
      new(attributes).claims
    end

    # JOSE header of every access token: the signing key's id and the
    # RFC 9068 media type.
    #
    # @return [Hash]
    def self.headers
      { kid: SigningKey.for(realm: :default).kid, typ: TYPE }
    end

    def initialize(attributes)
      @attributes = attributes
      @user = attributes[:resource_owner_id] && User.find_by(id: attributes[:resource_owner_id])
      @client_uid = attributes[:application]&.uid
      @scopes = Array(attributes[:scopes]&.to_a).map(&:to_s)
      @issued_at = attributes[:created_at]&.to_i || Time.now.utc.to_i
    end

    def claims
      registered_claims.merge(user_claims)
    end

    private

    attr_reader :attributes, :user, :client_uid, :scopes, :issued_at

    def registered_claims
      {
        iss: Resources.issuer,
        sub: user&.sso_id || client_uid,
        aud: attributes[:resource].presence || client_uid,
        azp: client_uid,
        scope: scopes.join(" "),
        scopes: scopes,
        jti: SecureRandom.uuid,
        iat: issued_at,
        nbf: issued_at,
        exp: issued_at + attributes[:expires_in].to_i
      }
    end

    def user_claims
      claims = { admin: user&.is_admin == true }
      return claims unless user

      claims[:name] = user.name if scopes.include?("profile")
      if scopes.include?("email")
        claims[:email] = user.email
        claims[:email_verified] = user.confirmed_at.present?
      end
      claims
    end
  end
end
