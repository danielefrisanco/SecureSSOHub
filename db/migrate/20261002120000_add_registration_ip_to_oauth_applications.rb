# Dynamic client registration (RFC 7591, TASK-025) is unauthenticated, so
# until rate limiting lands (T24) the hub caps registrations per source
# address and hour with a count over this column; an administrator reviewing
# a pending client also sees where it came from. Null for clients an
# administrator created.
class AddRegistrationIpToOAuthApplications < ActiveRecord::Migration[8.1]
  def change
    add_column :oauth_applications, :registration_ip, :inet
    add_index :oauth_applications, %i[registration_ip created_at]
  end
end
