require "base64"
require "digest"

module OAuth
  # The id_token the token endpoint returns with the `openid` scope
  # (doorkeeper-openid_connect builds iss/sub/aud/exp/iat/nonce/auth_time and
  # the scope-gated claims configured in doorkeeper_openid_connect.rb).
  #
  # Added here: `at_hash` (OIDC Core §3.1.3.6 — optional in the code flow,
  # but the hub's clients get it so they can bind the id_token to the access
  # token they received with it). The gem's own at_hash variant hashes the
  # stored token value, which is a SHA-256 digest since tokens are hashed at
  # rest; the hash must be over the JWT the client actually holds.
  class IdToken < Doorkeeper::OpenidConnect::IdToken
    def claims
      super.merge(at_hash: at_hash)
    end

    private

    # Left-most half of the SHA-256 of the access token, base64url without
    # padding (RS256 → SHA-256). The plaintext JWT only exists on the record
    # that was just created; without it the claim is left out rather than
    # computed over the wrong value.
    def at_hash
      plaintext = @access_token.plaintext_token
      return nil if plaintext.blank?

      digest = Digest::SHA256.digest(plaintext)
      Base64.urlsafe_encode64(digest[0, digest.bytesize / 2], padding: false)
    end
  end
end
