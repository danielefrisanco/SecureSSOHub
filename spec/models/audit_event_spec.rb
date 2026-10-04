require "rails_helper"

# The audit log is append-only (TASK-029): a saved event cannot be changed or
# removed through the model.
RSpec.describe AuditEvent do
  let(:event) { described_class.create!(event: "user.signed_in", subject_id: 1) }

  it "accepts only the catalogued events" do
    expect(described_class.new(event: "user.signed_in")).to be_valid
    expect(described_class.new(event: "user.renamed")).not_to be_valid
  end

  it "stamps created_at and has no updated_at" do
    expect(event.created_at).to be_present
    expect(described_class.column_names).not_to include("updated_at")
  end

  it "cannot be updated" do
    expect { event.update!(subject_id: 2) }.to raise_error(ActiveRecord::ReadOnlyRecord)
    expect(event.reload.subject_id).to eq(1)
  end

  it "cannot be destroyed or deleted" do
    expect { event.destroy }.to raise_error(ActiveRecord::ReadOnlyRecord)
    expect { event.delete }.to raise_error(ActiveRecord::ReadOnlyRecord)
    expect(described_class.exists?(event.id)).to be(true)
  end
end
