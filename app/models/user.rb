class User < ApplicationRecord
  # Accounts are created by an admin, so :registerable is deliberately off.
  # :confirmable makes `email_verified` mean something (TASK-030): no sign-in
  # until the address is confirmed, and a changed address is confirmed again.
  devise :database_authenticatable, :recoverable, :rememberable, :validatable,
         :trackable, :lockable, :timeoutable, :confirmable

  # A new password must not appear in a known breach (TASK-030). Checked only
  # when it is being stored (Devise keeps `password` on the record after a
  # save) and has passed Devise's own rules, so a too-short one costs no API call.
  validates :password, not_breached: true, if: :new_password_to_check?

  # Validation to ensure the sso_id is present and unique.
  validates :sso_id, presence: true, uniqueness: true

  # Callback to ensure a stable, globally unique ID (sso_id) is set
  # before the user record is saved.
  before_validation :set_sso_id, on: :create

  # Sign out everywhere — every OAuth token and pending code of the user, all
  # clients — when the password changes (reset or update) or an administrator
  # disables the account. Signing out of the hub revokes nothing, nor does a
  # failed-attempts lock, which anyone can trigger (docs/ARCHITECTURE.md §3).
  # The audit log (TASK-029) records these changes, a failed-attempts lock and
  # an email confirmation, in the same transaction as the update.
  after_update :record_audit_events
  after_update :revoke_oauth_tokens, if: :oauth_tokens_invalidated?

  private

  def new_password_to_check?
    will_save_change_to_encrypted_password? && password.present? && errors[:password].empty?
  end

  def record_audit_events
    Audit.record("user.password_changed", subject_id: id) if saved_change_to_encrypted_password?
    Audit.record("user.disabled", subject_id: id) if saved_change_to_disabled_at? && disabled_at.present?
    if saved_change_to_confirmed_at? && confirmed_at.present?
      Audit.record("user.email_confirmed", subject_id: id, reconfirmation: saved_change_to_email?)
    end
    return unless saved_change_to_locked_at? && locked_at.present?

    Audit.record("user.locked", actor: nil, subject_id: id, failed_attempts: failed_attempts)
  end

  def oauth_tokens_invalidated?
    saved_change_to_encrypted_password? || (saved_change_to_disabled_at? && disabled_at.present?)
  end

  def revoke_oauth_tokens
    OAuth::Tokens.revoke_all_for(user: self)
  end

  # Generates a unique UUID if sso_id is not already present.
  # This UUID is the non-email identifier used across all trusting services.
  def set_sso_id
    self.sso_id = SecureRandom.uuid unless sso_id.present?
  end
end
