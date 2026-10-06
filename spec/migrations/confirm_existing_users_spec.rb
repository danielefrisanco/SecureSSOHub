require "rails_helper"
require Rails.root.join("db/migrate/20261006120000_confirm_existing_users")

# Accounts that existed before :confirmable were created by administrators and
# are marked confirmed (TASK-030, docs/ARCHITECTURE.md §5).
RSpec.describe ConfirmExistingUsers do
  it "confirms every unconfirmed account and leaves confirmed ones as they were" do
    unconfirmed = create(:user, :unconfirmed)
    confirmed_at = 1.year.ago.change(usec: 0)
    confirmed = create(:user, confirmed_at: confirmed_at)

    ActiveRecord::Migration.suppress_messages { described_class.new.up }

    expect(unconfirmed.reload).to be_confirmed
    expect(confirmed.reload.confirmed_at).to eq(confirmed_at)
  end
end
