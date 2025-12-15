source "https://rubygems.org"
git_source(:github) { |repo| "https://github.com/#{repo}.git" }

# Specify the required Ruby version to match your local setup
ruby "3.1.4" 

# --- Core Rails Dependencies ---
gem "rails", "~> 7.1", ">= 7.1.3"
gem "bootsnap", require: false
gem "pg", "~> 1.1" # Database adapter
gem "puma", "~> 6.0"
gem "importmap-rails"
gem "turbo-rails"
gem "stimulus-rails"
gem "jbuilder"
gem "sassc-rails"

# --- Authentication & Security Gems ---
# User management framework
gem "devise", "~> 4.9" 
# Core OmniAuth framework (required by the providers)
gem "omniauth", "~> 2.1" 
# Your custom gems (assuming these are built/sourced locally)
gem "jwt_auth_client"
gem "rack-jwt-verifier" 
gem "omniauth-ssoprovider", "~> 0.1.2"
gem "omniauth_syncer"
gem "header_guard"
# Cross-Origin Resource Sharing (essential for SSO architecture)
gem "rack-cors"
# Essential security gem for all OmniAuth setups

gem "omniauth-rails_csrf_protection"
# --- Testing & Development ---
group :development, :test do
  gem "rspec-rails", "~> 6.0"
  gem "factory_bot_rails"
  gem "faker"
  # Debugging tools
  gem "pry-rails"
  gem "dotenv-rails"
end

group :test do
  gem "webmock", "~> 3.19"
  gem "timecop", "~> 0.9"
end
# --- Authentication & SSO Gems ---
# The core gem that makes this app an SSO Provider strategy for OmniAuth
gem "omniauth-ssoprovider", "~> 0.1.2"

# Core JWT library for signing and handling tokens (required by both SSO and your client)
gem "jwt", "~> 2.8" 

