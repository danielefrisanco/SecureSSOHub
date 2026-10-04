require "rails_helper"
require "open3"

# Rails.cache must be shared across processes in production (TASK-027): rate
# limits and readiness would silently disagree between Puma workers on a
# per-process store. Booting production is the only honest check of
# config/environments/production.rb, so this spawns `rails runner`;
# SECRET_KEY_BASE_DUMMY stands in for the signing key and nothing dials Redis
# (the store connects on first use).
RSpec.describe "Cache store" do
  def boot_production(env)
    base = { "RAILS_ENV" => "production", "SECRET_KEY_BASE_DUMMY" => "1",
             "HUB_ISSUER" => "https://hub.test", "REDIS_URL" => nil }
    script = "print Rails.cache.class.name, ' ', Rails.application.config.cache_store.last[:url]"
    Open3.capture2e(base.merge(env), "bin/rails", "runner", script, chdir: Rails.root.to_s)
  end

  it "is Redis from REDIS_URL in production" do
    output, status = boot_production("REDIS_URL" => "redis://cache.invalid:6379/0")

    expect(status).to be_success, output
    expect(output).to include("ActiveSupport::Cache::RedisCacheStore redis://cache.invalid:6379/0")
  end

  it "stops the production boot when REDIS_URL is missing" do
    output, status = boot_production({})

    expect(status).not_to be_success
    expect(output).to include("REDIS_URL is not set: the hub refuses to boot without its shared cache")
  end

  it "is in memory in test" do
    expect(Rails.cache).to be_a(ActiveSupport::Cache::MemoryStore)
  end
end
