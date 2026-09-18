require "rails_helper"

# The authorization-server core (Doorkeeper) is an implementation detail hidden
# behind app/services/oauth so it can be replaced (docs/ARCHITECTURE.md §4).
# Anything else under app/ that names a Doorkeeper constant is a leak.
RSpec.describe "Doorkeeper isolation", type: :architecture do
  let(:allowed_dirs) { %w[app/services/oauth/] }

  it "keeps Doorkeeper:: references inside app/services/oauth" do
    offenders = Rails.root.glob("app/**/*.{rb,erb}").filter_map do |path|
      relative = path.relative_path_from(Rails.root).to_s
      next if allowed_dirs.any? { |dir| relative.start_with?(dir) }

      relative if path.read.match?(/\bDoorkeeper::/)
    end

    expect(offenders).to be_empty, "Doorkeeper:: referenced outside app/services/oauth:\n  #{offenders.join("\n  ")}"
  end
end
