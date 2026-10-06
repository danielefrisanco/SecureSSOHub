require "rails_helper"
require "support/hub_access_token"

# :confirmable (TASK-030): an account an administrator creates cannot sign in
# until its address is confirmed through the mailed link; from then on
# `email_verified` is true in the id_token, the access token and userinfo.
RSpec.describe "Email confirmation", type: :request do
  include HubAccessToken

  let(:password) { "correct horse battery staple" }
  let!(:user) { create(:user, :unconfirmed, name: "Ada Lovelace", password: password) }
  let(:client) { create(:oauth_client, :public, scopes: "openid profile email") }

  def last_mail
    ActionMailer::Base.deliveries.last
  end

  def confirmation_token(mail)
    mail.body.encoded[/confirmation_token=([\w-]+)/, 1]
  end

  # Route helpers, not bare paths: they load the routes before Warden sees the
  # request (the cold-process issue noted in TASK-029).
  def sign_in_with_password
    post user_session_path, params: { user: { email: user.email, password: password } }
  end

  def claims(jwt)
    get "/.well-known/jwks.json"
    JWT.decode(jwt, nil, true, algorithms: ["RS256"], jwks: JWT::JWK::Set.new(response.parsed_body)).first
  end

  it "mails a confirmation link from MAILER_FROM when the account is created" do
    expect(ActionMailer::Base.deliveries.size).to eq(1)
    expect(last_mail).to have_attributes(to: [user.email], from: ["no-reply@localhost"],
                                         subject: "Confirmation instructions")
    expect(confirmation_token(last_mail)).to be_present
  end

  it "refuses to sign in an unconfirmed account" do
    sign_in_with_password
    follow_redirect!

    expect(response.body).to include("You have to confirm your email address before continuing.")
    expect(controller.current_user).to be_nil
  end

  it "confirms through the mailed link; then the user signs in and every document says email_verified" do
    get user_confirmation_path(confirmation_token: confirmation_token(last_mail))
    expect(user.reload).to be_confirmed
    expect(AuditEvent.where(event: "user.email_confirmed").last)
      .to have_attributes(subject_id: user.id, metadata: { "reconfirmation" => false })

    sign_in_with_password
    expect(response).to redirect_to(root_path)
    sign_out user

    tokens = obtain_token_response(user: user, client: client, scope: "openid profile email",
                                   resource: OAuth::Resources.hub_api)
    expect(claims(tokens.fetch("id_token"))).to include("email" => user.email, "email_verified" => true)
    expect(claims(tokens.fetch("access_token"))).to include("email" => user.email, "email_verified" => true)
    get "/api/v1/userinfo", headers: { "Authorization" => "Bearer #{tokens.fetch('access_token')}" }
    expect(response.parsed_body).to include("email" => user.email, "email_verified" => true)
    get "/oauth/userinfo", headers: { "Authorization" => "Bearer #{tokens.fetch('access_token')}" }
    expect(response.parsed_body).to include("email" => user.email, "email_verified" => true)
  end

  it "refuses a link older than three days; the user asks for a new one" do
    token = confirmation_token(last_mail)

    Timecop.travel(4.days.from_now) do
      get user_confirmation_path(confirmation_token: token)
      expect(response.body).to include("needs to be confirmed within 3 days, please request a new one")
      expect(user.reload).not_to be_confirmed

      expect { post user_confirmation_path, params: { user: { email: user.email } } }
        .to change { ActionMailer::Base.deliveries.size }.by(1)
      get user_confirmation_path(confirmation_token: confirmation_token(last_mail))
      expect(user.reload).to be_confirmed
    end
  end

  it "confirms a changed address again and keeps the confirmed one until then" do
    confirmed = create(:user, email: "ada@example.com")
    confirmed.update!(email: "ada@new.example.com")

    expect(confirmed.reload).to have_attributes(email: "ada@example.com", unconfirmed_email: "ada@new.example.com")
    expect(last_mail.to).to eq(["ada@new.example.com"])

    get user_confirmation_path(confirmation_token: confirmation_token(last_mail))
    expect(confirmed.reload).to have_attributes(email: "ada@new.example.com", unconfirmed_email: nil)
    expect(AuditEvent.where(event: "user.email_confirmed").last.metadata).to eq("reconfirmation" => true)
  end
end
