# frozen_string_literal: true

class DeviseCreateUsers < ActiveRecord::Migration[7.1]
  def change
    create_table :users do |t|
      ## SSO Identity Fields (Replaces Database Authenticatable)
      # sso_id will store the unique identifier from the Identity Provider
      t.string :sso_id, null: false, default: ""

      ## Profile Fields
      t.string :name
      t.string :email,              null: false, default: ""

      ## Authorization (Basic App Role)
      t.boolean :is_admin, default: false

      ## Rememberable (Kept for Devise session management)
      t.datetime :remember_created_at

      ## Trackable (Optional, but useful)
      t.integer  :sign_in_count, default: 0, null: false
      t.datetime :current_sign_in_at
      t.datetime :last_sign_in_at
      t.string   :current_sign_in_ip
      t.string   :last_sign_in_ip

      t.timestamps null: false
    end

    # Index sso_id as the primary unique identifier for login
    add_index :users, :sso_id, unique: true
    # Keep email indexed for lookup purposes
    add_index :users, :email,  unique: true
  end
end
