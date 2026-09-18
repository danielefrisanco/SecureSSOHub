# Devise was configured with :database_authenticatable and :recoverable, but the
# original migration never created their columns, so nobody could sign in. Adds
# the columns for every Devise module the hub uses now (:lockable, :timeoutable,
# :trackable already had columns) or will use next (:confirmable — enabled in a
# later task once a mailer is configured), plus `disabled_at` for admin disabling.
class AddDeviseColumnsToUsers < ActiveRecord::Migration[7.1]
  def change
    change_table :users, bulk: true do |t|
      ## Database authenticatable
      t.string :encrypted_password, null: false, default: ""

      ## Recoverable
      t.string   :reset_password_token
      t.datetime :reset_password_sent_at

      ## Confirmable (columns only; module enabled later)
      t.string   :confirmation_token
      t.datetime :confirmed_at
      t.datetime :confirmation_sent_at
      t.string   :unconfirmed_email

      ## Lockable
      t.integer  :failed_attempts, default: 0, null: false
      t.string   :unlock_token
      t.datetime :locked_at

      ## Hub-specific: set by an admin to block sign-in without deleting the account
      t.datetime :disabled_at
    end

    add_index :users, :reset_password_token, unique: true
    add_index :users, :confirmation_token,   unique: true
    add_index :users, :unlock_token,         unique: true
  end
end
