require "open3"

# Boots the app in production with `rails runner` — the only honest check of
# config/environments/production.rb and of the settings that stop the boot.
# SECRET_KEY_BASE_DUMMY stands in for the signing key; the required settings
# get reserved (.invalid) placeholders, and nothing dials Redis or the mail
# server (both connect on first use). A spec overrides or removes (nil) any of
# them through `env`.
module ProductionBoot
  REQUIRED_ENV = {
    "RAILS_ENV" => "production", "SECRET_KEY_BASE_DUMMY" => "1", "HUB_ISSUER" => "https://hub.test",
    "REDIS_URL" => "redis://cache.invalid:6379/0", "SMTP_ADDRESS" => "smtp.mail.invalid",
    "MAILER_FROM" => "Secure SSO Hub <no-reply@hub.test>"
  }.freeze

  # @param script [String] Ruby run once the app has booted; print what to check
  # @param env [Hash{String => String, nil}] overrides of REQUIRED_ENV
  # @return [Array(String, Process::Status)] combined output and exit status
  def boot_production(script, env = {})
    Open3.capture2e(REQUIRED_ENV.merge(env), "bin/rails", "runner", script, chdir: Rails.root.to_s)
  end
end
