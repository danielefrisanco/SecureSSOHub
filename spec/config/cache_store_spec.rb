require "rails_helper"
require "support/production_boot"

# Rails.cache must be shared across processes in production (TASK-027): rate
# limits and readiness would silently disagree between Puma workers on a
# per-process store.
RSpec.describe "Cache store" do
  include ProductionBoot

  let(:script) { "print Rails.cache.class.name, ' ', Rails.application.config.cache_store.last[:url]" }

  it "is Redis from REDIS_URL in production" do
    output, status = boot_production(script)

    expect(status).to be_success, output
    expect(output).to include("ActiveSupport::Cache::RedisCacheStore redis://cache.invalid:6379/0")
  end

  it "stops the production boot when REDIS_URL is missing" do
    output, status = boot_production(script, "REDIS_URL" => nil)

    expect(status).not_to be_success
    expect(output).to include("REDIS_URL is not set: the hub refuses to boot without its shared cache")
  end

  it "is in memory in test" do
    expect(Rails.cache).to be_a(ActiveSupport::Cache::MemoryStore)
  end
end
