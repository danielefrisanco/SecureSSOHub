source "https://rubygems.org"
git_source(:github) { |repo| "https://github.com/#{repo}.git" }

# Specify the required Ruby version to match your local setup
ruby "3.4.10"

# --- Core Rails Dependencies ---
gem "bootsnap", require: false
# Asset pipeline (Rails 8 defaults to Propshaft; the hub stays on sprockets for now)
gem "importmap-rails"
gem "jbuilder"
gem "pg", "~> 1.1" # Database adapter
gem "puma", "~> 7.2", ">= 7.2.1"
gem "rails", "~> 8.1"
gem "sprockets-rails"
gem "stimulus-rails"
gem "turbo-rails"

# --- Authentication & Security Gems ---
# User management framework
gem "devise", "~> 5.0", ">= 5.0.4"
# Own gems (published on rubygems.org). The hub is the OAuth *provider*: it
# verifies bearer tokens on its own API (rack-jwt-verifier) and hardens
# responses (header_guard); access tokens are minted by doorkeeper-jwt below.
# Client-side gems live in the test group below.
gem "header_guard", "~> 0.3"
gem "rack-jwt-verifier", "~> 0.3"
# OAuth 2.1 / OpenID Connect authorization server core (ARCHITECTURE §4): kept behind
# app/services/oauth so it can be swapped for an own gem later.
gem "doorkeeper", "~> 5.9"
gem "doorkeeper-jwt", "~> 0.4"
gem "doorkeeper-openid_connect", "~> 1.10"
# Cross-Origin Resource Sharing (essential for SSO architecture)
gem "rack-cors"
# --- Testing & Development ---
group :development, :test do
  # Reference OAuth *client* used only to exercise the hub end to end in specs.
  gem "omniauth-oauth2"
  gem "omniauth-ssoprovider", "~> 0.1.2", require: "omniauth/strategies/ssoprovider"
  gem "rspec-rails", "~> 6.0"
  # Lint and security scanners, run in CI (`bundle exec rubocop`, brakeman, bundler-audit)
  gem "brakeman", require: false
  gem "bundler-audit", require: false
  gem "factory_bot_rails"
  gem "faker"
  gem "rubocop", require: false
  gem "rubocop-rails", require: false
  gem "rubocop-rspec", require: false
  # Debugging tools
  gem "dotenv-rails"
  gem "pry-rails"
end

group :test do
  gem "timecop", "~> 0.9"
  gem "webmock", "~> 3.19"
end

# Core JWT library for signing and handling tokens (required by both SSO and your client)
gem "jwt", "~> 2.8"
# json 3.x removed JSON.parse's positional options hash, which rack-session 2.1.2
# (the newest release) still passes: every request raises ArgumentError. Stay on
# the maintained 2.x line until rack-session is fixed upstream.
gem "json", "~> 2.21"
