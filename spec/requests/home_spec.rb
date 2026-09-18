require 'rails_helper'

RSpec.describe "Landing page", type: :request do
  it "invites visitors to sign in" do
    get root_path
    expect(response).to have_http_status(:ok)
    expect(response.body).to include("Secure SSO Hub", "Sign in")
    expect(response.body).to include(new_user_session_path)
  end

  it "greets a signed-in user" do
    user = create(:user, name: "Ada")
    sign_in user
    get root_path
    expect(response).to have_http_status(:ok)
    expect(response.body).to include("Hello, Ada", "Sign out")
  end

  it "shows the administration entry only to admins" do
    sign_in create(:user, :admin)
    get root_path
    expect(response.body).to include("Administration")

    sign_in create(:user)
    get root_path
    expect(response.body).not_to include("Administration")
  end
end
