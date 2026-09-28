# Access tokens are self-contained JWTs, so a resource server that verified the
# signature still has to ask the hub whether the token was revoked. The JWT
# carries `jti`; the row stores only a hash of the whole token, which the
# claims alone cannot reproduce. Storing the `jti` on the row (set before the
# JWT is generated, OAuth::TokenRecord) makes revocation a single indexed lookup
# from the claims (OAuth::Tokens.active?).
#
# Nullable: tokens issued before this column have no jti and are treated as
# revoked by that lookup; they expire within ten minutes anyway.
class AddJtiToOAuthAccessTokens < ActiveRecord::Migration[8.1]
  def change
    add_column :oauth_access_tokens, :jti, :string
    add_index :oauth_access_tokens, :jti, unique: true
  end
end
