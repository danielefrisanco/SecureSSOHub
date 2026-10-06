require "rails_helper"
require "support/production_boot"

# Mail in production (TASK-030): any SMTP server, configured from env; the boot
# stops without a server or a sender, since no account could be confirmed or
# recovered.
RSpec.describe "Mail settings" do
  include ProductionBoot

  let(:script) do
    'require "json"; base = ActionMailer::Base; ' \
      "print({ method: base.delivery_method, raise: base.raise_delivery_errors, smtp: base.smtp_settings, " \
      "url: base.default_url_options, from: Devise.mailer_sender }.to_json)"
  end

  def boot_mail(env = {})
    output, status = boot_production(script, env)
    expect(status).to be_success, output
    JSON.parse(output.lines.last)
  end

  it "delivers through the SMTP server from env and links to the issuer" do
    mail = boot_mail("SMTP_PORT" => "2525", "SMTP_USERNAME" => "hub", "SMTP_PASSWORD" => "not-a-real-one")

    expect(mail).to include("method" => "smtp", "raise" => true, "from" => "Secure SSO Hub <no-reply@hub.test>",
                            "url" => { "host" => "hub.test", "port" => 443, "protocol" => "https" })
    expect(mail["smtp"]).to include("address" => "smtp.mail.invalid", "port" => 2525, "domain" => "hub.test",
                                    "user_name" => "hub", "authentication" => "plain")
    expect(mail["smtp"]["password"]).to be_present
  end

  it "requires STARTTLS when there is a password to send, and tries it otherwise" do
    expect(boot_mail("SMTP_USERNAME" => "hub")["smtp"]).to include("port" => 587, "enable_starttls" => "always")

    relay = boot_mail["smtp"]
    expect(relay).to include("enable_starttls" => "auto")
    expect(relay.keys).not_to include("user_name", "authentication")
  end

  it "speaks TLS from the first byte on port 465" do
    smtp = boot_mail("SMTP_PORT" => "465", "SMTP_USERNAME" => "hub")["smtp"]
    expect(smtp).to include("tls" => true)
    expect(smtp.keys).not_to include("enable_starttls")
  end

  it "stops the production boot without a mail server, a sender or a valid port" do
    {
      { "SMTP_ADDRESS" => nil } => "SMTP_ADDRESS is not set: the hub refuses to boot without a mail server",
      { "MAILER_FROM" => nil } => "MAILER_FROM is not set: the hub cannot send mail",
      { "SMTP_PORT" => "smtp" } => 'SMTP_PORT must be a TCP port number, got "smtp"'
    }.each do |env, message|
      output, status = boot_production(script, env)
      expect(status).not_to be_success
      expect(output).to include(message)
    end
  end
end
