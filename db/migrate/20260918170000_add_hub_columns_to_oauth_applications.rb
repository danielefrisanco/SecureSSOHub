# The hub's client registry on top of Doorkeeper's oauth_applications
# (TASK-016): client type, approval workflow for dynamic registration,
# ownership, RFC 7591 metadata and usage tracking. `secret` becomes nullable
# because public clients (native apps, MCP clients using PKCE) have none.
class AddHubColumnsToOAuthApplications < ActiveRecord::Migration[8.1]
  def change
    change_table :oauth_applications, bulk: true do |t|
      t.string :client_type, null: false, default: "confidential"
      t.string :approval_state, null: false, default: "approved"
      # Existing rows predate dynamic registration, hence the default.
      t.string :registered_via, null: false, default: "admin"
      t.references :owner, foreign_key: { to_table: :users }
      t.string :software_id
      t.string :software_version
      t.string :client_uri
      t.string :logo_uri
      t.jsonb :contacts
      t.datetime :last_used_at
    end
    add_index :oauth_applications, :approval_state
    change_column_null :oauth_applications, :secret, true
  end
end
