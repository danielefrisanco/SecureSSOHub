require "rails_helper"

# Pwned Passwords range API (TASK-030), by k-anonymity.
RSpec.describe PwnedPasswords do
  let(:password) { "a long but famous passphrase" }
  let(:digest) { Digest::SHA1.hexdigest(password).upcase }
  let(:range_url) { "https://api.pwnedpasswords.com/range/#{digest[0, 5]}" }

  def stub_range(*lines, status: 200)
    stub_request(:get, range_url).with(headers: { "Add-Padding" => "true" })
      .to_return(status: status, body: lines.join("\r\n"))
  end

  it "finds a password whose hash suffix is in the range" do
    stub_range("0018A45C4D1DEF81644B54AB7F969B88D65:1", "#{digest[5..]}:3861493")
    expect(described_class.breached?(password)).to be true
  end

  it "sends the first five characters of the hash and nothing else" do
    stub_range("0018A45C4D1DEF81644B54AB7F969B88D65:1")

    expect(described_class.breached?(password)).to be false
    expect(WebMock).to(have_requested(:get, range_url).with { |request| request.body.blank? })
  end

  it "ignores the padding entries, which carry a count of 0" do
    stub_range("#{digest[5..]}:0")
    expect(described_class.breached?(password)).to be false
  end

  it "is unavailable when the API cannot be reached or answers with an error" do
    stub_request(:get, range_url).to_timeout
    expect { described_class.breached?(password) }.to raise_error(PwnedPasswords::Unavailable, /Timeout/)

    stub_request(:get, range_url).to_raise(Errno::ECONNREFUSED)
    expect { described_class.breached?(password) }.to raise_error(PwnedPasswords::Unavailable, /ECONNREFUSED/)

    stub_range(status: 503)
    expect { described_class.breached?(password) }.to raise_error(PwnedPasswords::Unavailable, "HTTP 503")
  end
end
