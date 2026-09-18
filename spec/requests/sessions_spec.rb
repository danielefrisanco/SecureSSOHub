require 'rails_helper'

RSpec.describe "Devise sessions", type: :request do
  let(:password) { "correct horse battery staple" }
  let!(:user) { create(:user, password: password) }

  it "signs in with valid credentials" do
    post user_session_path, params: { user: { email: user.email, password: password } }
    expect(response).to redirect_to(root_path)
    expect(user.reload.sign_in_count).to eq(1)
  end

  it "rejects invalid credentials" do
    post user_session_path, params: { user: { email: user.email, password: "nope" } }
    expect(response).to have_http_status(422)
    expect(user.reload.failed_attempts).to eq(1)
  end
end
