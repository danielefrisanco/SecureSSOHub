# :confirmable is switched on (TASK-030). Accounts that exist already were
# created by administrators, so they are marked confirmed rather than shut out
# until they answer a mail (decision: docs/ARCHITECTURE.md §5). The columns
# have existed since TASK-006.
class ConfirmExistingUsers < ActiveRecord::Migration[8.1]
  def up
    execute "UPDATE users SET confirmed_at = CURRENT_TIMESTAMP WHERE confirmed_at IS NULL"
  end

  def down
    # Nothing to undo: which accounts this confirmed is not recorded, and a
    # confirmed_at left behind means nothing without :confirmable.
  end
end
