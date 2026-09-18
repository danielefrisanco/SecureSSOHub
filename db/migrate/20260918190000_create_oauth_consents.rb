# Persisted user consent per client (TASK-018): once a user has allowed a
# client a set of scopes, later authorizations for the same client and a
# subset of those scopes skip the consent page. Revoking sets revoked_at
# (history is kept for the account page); at most one live consent exists
# per user and client.
class CreateOAuthConsents < ActiveRecord::Migration[8.1]
  def change
    create_table :oauth_consents do |t|
      t.references :user, null: false, foreign_key: true
      t.references :oauth_application, null: false, foreign_key: true
      t.string :scopes, null: false, default: ""
      t.datetime :granted_at, null: false
      t.datetime :revoked_at

      t.timestamps
    end

    add_index :oauth_consents, %i[user_id oauth_application_id], unique: true, where: "revoked_at IS NULL",
                                                                 name: "index_oauth_consents_live_per_user_and_client"
  end
end
