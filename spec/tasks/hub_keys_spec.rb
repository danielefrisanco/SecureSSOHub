require "rails_helper"
require "rake"

RSpec.describe "hub:keys rake tasks" do
  before do
    Rails.application.load_tasks if Rake::Task.tasks.empty?
  end

  def run_task(name)
    task = Rake::Task[name]
    task.reenable
    output = StringIO.new
    $stdout = output
    task.invoke
    output.string
  ensure
    $stdout = STDOUT
  end

  it "hub:keys:generate prints a fresh key in the OIDC_SIGNING_KEY format with its kid" do
    output = run_task("hub:keys:generate")
    line = output.lines.find { |l| l.start_with?("OIDC_SIGNING_KEY=") }
    expect(line).to be_present
    encoded = line.delete_prefix("OIDC_SIGNING_KEY=").strip
    key = OAuth::SigningKey.parse(encoded)
    expect(key.n.num_bits).to be >= 2048
    expect(output).to include("# kid: #{OAuth::SigningKey.new([key.to_pem]).kid}")
    expect(output).to include("OIDC_SIGNING_KEY_PREVIOUS")
  end

  it "hub:keys:show prints the loaded kids" do
    output = run_task("hub:keys:show")
    keys = OAuth::SigningKey.for(realm: :default)
    expect(output).to include("active:   #{keys.kid}")
    expect(output).to include("previous: (none)")
  end
end
