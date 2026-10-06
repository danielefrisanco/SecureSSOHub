require "active_support/core_ext/integer/time"

Rails.application.configure do
  # Settings specified here will take precedence over those in config/application.rb.

  # Code is not reloaded between requests.
  config.enable_reloading = false

  # Eager load code on boot for better performance and memory savings (ignored by Rake tasks).
  config.eager_load = true

  # Full error reports are disabled.
  config.consider_all_requests_local = false

  # Turn on fragment caching in view templates.
  config.action_controller.perform_caching = true

  # Cache assets for far-future expiry since they are all digest stamped.
  config.public_file_server.headers = { "cache-control" => "public, max-age=#{1.year.to_i}" }

  # sprockets: never compile assets on demand in production.
  config.assets.compile = false

  # Enable serving of images, stylesheets, and JavaScripts from an asset server.
  # config.asset_host = "http://assets.example.com"

  # Assume all access to the app is happening through a SSL-terminating reverse proxy.
  config.assume_ssl = true

  # Force all access to the app over SSL, use Strict-Transport-Security, and use secure cookies.
  config.force_ssl = true

  # Skip http-to-https redirect for the default health check endpoint.
  # config.ssl_options = { redirect: { exclude: ->(request) { request.path == "/up" } } }

  # Log to STDOUT with the current request id as a default log tag.
  config.log_tags = [:request_id]
  config.logger   = ActiveSupport::TaggedLogging.logger(STDOUT)

  # Change to "debug" to log everything (including potentially personally-identifiable information!).
  config.log_level = ENV.fetch("RAILS_LOG_LEVEL", "info")

  # Prevent health checks from clogging up the logs.
  config.silence_healthcheck_path = "/up"

  # Don't log any deprecations.
  config.active_support.report_deprecations = false

  # Redis is the shared cache: rate-limit counters and the readiness check must
  # agree across Puma workers and hosts, which a per-process store cannot do.
  config.cache_store = :redis_cache_store, {
    url: ENV.fetch("REDIS_URL") { raise "REDIS_URL is not set: the hub refuses to boot without its shared cache" }
  }

  # Replace the default in-process and non-durable queuing backend for Active Job.
  # config.active_job.queue_adapter = :resque

  # Mail (TASK-030): Devise's confirmation, password-reset and unlock mails go
  # out through any SMTP server, configured from env. Without SMTP_ADDRESS (or
  # MAILER_FROM, config/initializers/devise.rb) the hub refuses to boot: no
  # account could be confirmed or recovered. A mail that cannot be delivered
  # fails the request instead of vanishing.
  smtp_port = ENV.fetch("SMTP_PORT", "587")
  unless Integer(smtp_port, 10, exception: false)&.between?(1, 65_535)
    raise "SMTP_PORT must be a TCP port number, got #{smtp_port.inspect}"
  end

  smtp_port = Integer(smtp_port, 10)
  smtp_username = ENV["SMTP_USERNAME"].presence
  # Links in mail point at the hub's canonical URL (HUB_ISSUER, required here
  # anyway — config/initializers/doorkeeper.rb).
  hub_url = URI(ENV.fetch("HUB_ISSUER") { raise "HUB_ISSUER is not set" })
  config.action_mailer.delivery_method = :smtp
  config.action_mailer.raise_delivery_errors = true
  config.action_mailer.default_url_options = { host: hub_url.host, port: hub_url.port, protocol: hub_url.scheme }
  smtp_address = ENV.fetch("SMTP_ADDRESS") do
    raise "SMTP_ADDRESS is not set: the hub refuses to boot without a mail server"
  end
  smtp_settings = {
    address: smtp_address,
    port: smtp_port,
    domain: hub_url.host,
    user_name: smtp_username,
    password: ENV["SMTP_PASSWORD"].presence,
    authentication: (:plain if smtp_username)
  }
  # Port 465 is TLS from the first byte. Elsewhere STARTTLS, required when there
  # is a password to send, so a server (or an attacker in between) that drops
  # STARTTLS cannot make the password travel in clear text.
  if smtp_port == 465
    smtp_settings[:tls] = true
  else
    smtp_settings[:enable_starttls] = smtp_username ? :always : :auto
  end
  config.action_mailer.smtp_settings = smtp_settings.compact

  # Enable locale fallbacks for I18n (makes lookups for any locale fall back to
  # the I18n.default_locale when a translation cannot be found).
  config.i18n.fallbacks = true

  # Do not dump schema after migrations.
  config.active_record.dump_schema_after_migration = false

  # Only use :id for inspections in production.
  config.active_record.attributes_for_inspect = [:id]

  # Enable DNS rebinding protection and other `Host` header attacks.
  # config.hosts = [
  #   "example.com",     # Allow requests from example.com
  #   /.*\.example\.com/ # Allow requests from subdomains like `www.example.com`
  # ]
  #
  # Skip DNS rebinding protection for the default health check endpoint.
  # config.host_authorization = { exclude: ->(request) { request.path == "/up" } }
end
