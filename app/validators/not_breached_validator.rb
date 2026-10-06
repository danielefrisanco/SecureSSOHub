# Refuses a password that appears in a known data breach (TASK-030), through
# PwnedPasswords. PASSWORD_BREACH_CHECK (config/initializers/password_breach_check.rb)
# decides what happens when the API cannot be reached: warn accepts the
# password and logs, block refuses it, off skips the check entirely.
class NotBreachedValidator < ActiveModel::EachValidator
  def validate_each(record, attribute, value)
    mode = Rails.configuration.x.password_breach_check
    return if mode == :off || value.blank?

    record.errors.add(attribute, :breached) if PwnedPasswords.breached?(value)
  rescue PwnedPasswords::Unavailable => e
    outcome = mode == :block ? "refused" : "accepted unchecked"
    Rails.logger.warn("Breached-password check unavailable (#{e.message}); password #{outcome}")
    record.errors.add(attribute, :breach_check_unavailable) if mode == :block
  end
end
