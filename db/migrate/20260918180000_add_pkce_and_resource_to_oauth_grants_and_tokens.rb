# PKCE (RFC 7636) and resource indicators (RFC 8707) on the authorization
# endpoint (TASK-017). Doorkeeper only stores and verifies a code challenge
# when oauth_access_grants has these columns; `resource` is carried from the
# grant to the token (Doorkeeper custom_access_token_attributes) so the token
# endpoint can set `aud`.
class AddPkceAndResourceToOAuthGrantsAndTokens < ActiveRecord::Migration[8.1]
  def change
    change_table :oauth_access_grants, bulk: true do |t|
      t.string :code_challenge
      t.string :code_challenge_method
      t.string :resource
    end
    add_column :oauth_access_tokens, :resource, :string
  end
end
