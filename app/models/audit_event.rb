# One entry of the audit log (TASK-029), written through Audit.record. The
# log is append-only: a saved event cannot be updated, destroyed or deleted
# through the model. Relation-level `update_all`/`delete_all` bypass Active
# Record, so the database grant (INSERT and SELECT only, TASK-033) is the
# real guarantee; nothing in the app calls them.
#
# The catalogue of events is documented in docs/ARCHITECTURE.md §4.
class AuditEvent < ApplicationRecord
  EVENTS = %w[
    user.signed_in user.sign_in_failed user.signed_out user.locked user.password_changed user.disabled
    consent.granted consent.revoked
    token.issued token.revoked token.refresh_reuse_detected token.code_replay_detected
    tokens.revoked_for_user tokens.revoked_for_user_and_client tokens.revoked_for_client
    client.created client.registered client.updated client.secret_rotated client.approved client.revoked
  ].freeze

  validates :event, inclusion: { in: EVENTS }

  def readonly?
    persisted? || super
  end

  # Active Record's `delete` skips the read-only check that `destroy` makes.
  def delete
    raise ActiveRecord::ReadOnlyRecord, "#{self.class} is append-only"
  end
end
