require "securerandom"

module OAuth
  # The hub's addition to Doorkeeper's access-token record, prepended into
  # Doorkeeper::AccessToken from config/initializers/doorkeeper.rb: the `jti`.
  #
  # The row stores only a hash of the JWT (hash_token_secrets), so a token
  # cannot be found again from its claims — and a resource server that verified
  # a self-contained JWT only has the claims. The `jti` is therefore chosen
  # here, on the record, *before* the JWT is generated, handed to
  # OAuth::TokenPayload through the generator attributes, and kept in the
  # indexed `oauth_access_tokens.jti` column that OAuth::Tokens.active? reads.
  module TokenRecord
    private

    # Doorkeeper::AccessToken#generate_token (before_validation on create).
    def generate_token
      self.jti ||= SecureRandom.uuid
      super
    end

    def attributes_for_token_generator
      super.merge(jti: jti)
    end
  end
end
