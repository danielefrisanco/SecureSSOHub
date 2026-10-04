require "rails_helper"

# Audit.record (TASK-029): request context, actor attribution, the metadata
# filter, and failing closed.
RSpec.describe Audit do
  let(:admin) { create(:user, :admin) }

  it "records the request's address, request id and signed-in user" do
    event = Current.set(ip: "203.0.113.9", request_id: "req-1", user: admin) do
      described_class.record("client.approved", client_uid: "abc", from: "pending")
    end

    expect(event).to have_attributes(event: "client.approved", actor_id: admin.id, client_uid: "abc",
                                     ip: IPAddr.new("203.0.113.9"), request_id: "req-1",
                                     metadata: { "from" => "pending" })
  end

  it "lets the caller name the actor, or none" do
    other = create(:user)
    Current.set(user: admin) do
      expect(described_class.record("user.disabled", actor: other, subject_id: other.id).actor_id).to eq(other.id)
      expect(described_class.record("user.locked", actor: nil, subject_id: other.id).actor_id).to be_nil
    end
  end

  it "stores metadata keys that look like credentials as [FILTERED] and drops nil values" do
    event = described_class.record("client.updated", password: "hunter2", client_secret: "s3cret",
                                                     refresh_token: "rt-1", private_key: "pem",
                                                     scopes: %w[openid], name: nil)

    expect(event.metadata).to eq("password" => "[FILTERED]", "client_secret" => "[FILTERED]",
                                 "refresh_token" => "[FILTERED]", "private_key" => "[FILTERED]",
                                 "scopes" => %w[openid])
  end

  it "raises on an event outside the catalogue" do
    expect { described_class.record("user.renamed") }.to raise_error(ActiveRecord::RecordInvalid)
  end

  describe "failing closed" do
    before { allow(AuditEvent).to receive(:create!).and_raise(ActiveRecord::StatementInvalid, "audit write failed") }

    it "rolls back a client registration it could not record" do
      expect do
        OAuth::Clients.create(name: "App", redirect_uris: ["https://app.test/cb"], client_type: :confidential,
                              scopes: %w[openid], by: admin)
      end.to raise_error(ActiveRecord::StatementInvalid)
      expect(OAuth::Clients.list).to be_empty
    end

    it "rolls back a password change it could not record" do
      user = create(:user)
      expect { user.update!(password: "a different passphrase") }.to raise_error(ActiveRecord::StatementInvalid)
      expect(user.reload.valid_password?("a different passphrase")).to be(false)
    end
  end
end
