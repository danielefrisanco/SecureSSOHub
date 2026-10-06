# Breached-password check (TASK-030): a new password found in Have I Been
# Pwned's Pwned Passwords is refused (PwnedPasswords, k-anonymity — only the
# first five characters of the password's SHA-1 leave the hub). Read and
# validated at boot; NotBreachedValidator reads it.
#
#   PASSWORD_BREACH_CHECK  warn (default): when the API cannot be reached the
#                          password is accepted and a warning logged — an
#                          outage does not stop password changes;
#                          block: the password is refused until the API answers;
#                          off: no check at all (hosts without internet access).
breach_check_modes = %w[warn block off]
breach_check_mode = ENV.fetch("PASSWORD_BREACH_CHECK", "warn")
unless breach_check_modes.include?(breach_check_mode)
  raise "PASSWORD_BREACH_CHECK must be one of #{breach_check_modes.join(', ')}, got #{breach_check_mode.inspect}"
end

Rails.application.config.x.password_breach_check = breach_check_mode.to_sym
