require "rails_helper"
require "open3"

# Rate-limit settings are validated at boot (config/initializers/rate_limits.rb
# and oauth_registration.rb, TASK-028): a typo must stop the boot, never lift
# a limit. Spawns `rails runner` because the check runs while booting.
RSpec.describe "Rate limit settings" do
  def boot(env)
    Open3.capture2e(env, "bin/rails", "runner", "print Rails.configuration.x.rate_limits.oauth_token",
                    chdir: Rails.root.to_s)
  end

  it "reads a limit from the environment" do
    output, status = boot("OAUTH_TOKEN_RATE_LIMIT" => "42")
    expect(status).to be_success, output
    expect(output).to end_with("42")
  end

  it "stops the boot on a value that is not a positive integer" do
    %w[0 -5 ten 1.5].each do |value|
      output, status = boot("SIGN_IN_RATE_LIMIT" => value)
      expect(status).not_to be_success
      expect(output).to include("SIGN_IN_RATE_LIMIT must be a positive integer (requests per window), " \
                                "got #{value.inspect}")
    end
  end

  it "validates the registration limit the same way" do
    output, status = boot("OAUTH_REGISTRATION_IP_LIMIT" => "0")
    expect(status).not_to be_success
    expect(output).to include("OAUTH_REGISTRATION_IP_LIMIT must be a positive integer")
  end
end
