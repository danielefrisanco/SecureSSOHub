# Token endpoint semantics (TASK-019).
#
# `access_grant_id` ties every access/refresh token to the authorization code
# it descends from (carried across refresh rotations): that is the "token
# family" revoked when a code is replayed, and the origin of the absolute
# refresh-token lifetime.
#
# Doorkeeper 5.9 reads its refresh-rotation policy from the schema: with a
# `previous_refresh_token` column the used refresh token stays valid until the
# new access token is first used through Doorkeeper's own bearer lookup (which
# the hub never does — its API verifies JWTs with rack-jwt-verifier), so the
# old refresh token would never be revoked. Without the column Doorkeeper
# revokes the used refresh token immediately, under a row lock — the strict
# rotation the hub wants.
class LinkOAuthAccessTokensToGrants < ActiveRecord::Migration[8.1]
  def change
    add_reference :oauth_access_tokens, :access_grant,
                  foreign_key: { to_table: :oauth_access_grants, on_delete: :nullify }
    remove_column :oauth_access_tokens, :previous_refresh_token, :string, default: "", null: false
  end
end
