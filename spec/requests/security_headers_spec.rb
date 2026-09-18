require 'rails_helper'

RSpec.describe "Security headers", type: :request do
  it "sends the header_guard set on every response" do
    get root_path
    expect(response.headers["strict-transport-security"]).to include("max-age=")
    expect(response.headers["x-frame-options"]).to eq("DENY")
    expect(response.headers["x-content-type-options"]).to eq("nosniff")
    expect(response.headers["referrer-policy"]).to eq("strict-origin-when-cross-origin")
    expect(response.headers["permissions-policy"]).to include("camera=()")
    expect(response.headers["cross-origin-opener-policy"]).to eq("same-origin-allow-popups")
  end

  it "sends a strict CSP whose nonce matches every inline script" do
    get root_path
    csp = response.headers["content-security-policy"]
    expect(csp).to include("default-src 'self'", "object-src 'none'", "frame-ancestors 'none'", "form-action 'self'")

    nonce = csp[/script-src[^;]*'nonce-([^']+)'/, 1]
    expect(nonce).to be_present, "script-src carries no nonce: #{csp}"

    inline_scripts = response.body.scan(/<script\b[^>]*>/).reject { |tag| tag.include?("src=") }
    expect(inline_scripts).not_to be_empty
    inline_scripts.each { |tag| expect(tag).to include(%(nonce="#{nonce}")) }
    expect(response.body).to include(%(<meta name="csp-nonce" content="#{nonce}"))
  end

  it "applies the same headers to Devise pages" do
    get new_user_session_path
    expect(response.headers["content-security-policy"]).to include("script-src 'self' 'nonce-")
    expect(response.headers["x-frame-options"]).to eq("DENY")
  end
end
