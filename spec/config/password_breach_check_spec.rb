require "rails_helper"
require "open3"

# PASSWORD_BREACH_CHECK is validated at boot
# (config/initializers/password_breach_check.rb, TASK-030): a typo must stop
# the boot, never switch the check off.
RSpec.describe "Breached-password check setting" do
  def boot(env)
    Open3.capture2e(env, "bin/rails", "runner", "print Rails.configuration.x.password_breach_check",
                    chdir: Rails.root.to_s)
  end

  it "warns by default and reads the mode from the environment" do
    output, status = boot("PASSWORD_BREACH_CHECK" => nil)
    expect(status).to be_success, output
    expect(output).to end_with("warn")

    output, = boot("PASSWORD_BREACH_CHECK" => "block")
    expect(output).to end_with("block")
  end

  it "stops the boot on an unknown mode" do
    output, status = boot("PASSWORD_BREACH_CHECK" => "false")
    expect(status).not_to be_success
    expect(output).to include('PASSWORD_BREACH_CHECK must be one of warn, block, off, got "false"')
  end
end
