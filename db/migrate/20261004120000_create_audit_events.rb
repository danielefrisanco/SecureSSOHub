# The audit log (TASK-029): one row per security-relevant event — sign-ins,
# consents, token issuance and revocation, client registry changes, account
# changes. Written only through Audit.record and never updated or deleted
# (AuditEvent is read-only once saved; a database grant that allows only
# INSERT and SELECT comes with the production deployment, TASK-033).
#
# The user and client columns hold identifiers, not foreign keys: the log
# outlives the rows it mentions, and a foreign key would either block a
# deletion or cascade into the log.
class CreateAuditEvents < ActiveRecord::Migration[8.1]
  def change
    create_table :audit_events do |t|
      t.string :event, null: false
      t.bigint :actor_id
      t.bigint :subject_id
      t.string :client_uid
      t.string :jti
      t.inet :ip
      t.string :request_id
      t.jsonb :metadata, null: false, default: {}
      t.datetime :created_at, null: false
    end

    add_index :audit_events, :created_at
    add_index :audit_events, %i[event created_at]
    add_index :audit_events, %i[subject_id created_at]
    add_index :audit_events, %i[actor_id created_at]
    add_index :audit_events, %i[client_uid created_at]
  end
end
