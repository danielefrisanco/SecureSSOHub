require 'rails_helper'

# The Devise pages must render inside the application layout (shared header
# and stylesheet), not the gem's bare defaults.
RSpec.describe "Devise views", type: :request do
  shared_examples "a page in the application layout" do |path_helper|
    it "renders #{path_helper} in the layout" do
      get public_send(path_helper)
      expect(response).to have_http_status(:ok)
      expect(response.body).to include('class="site-header"', '/assets/application')
    end
  end

  include_examples "a page in the application layout", :new_user_session_path
  include_examples "a page in the application layout", :new_user_password_path
  include_examples "a page in the application layout", :new_user_unlock_path

  it "renders the sign-in form without a sign-up link" do
    get new_user_session_path
    expect(response.body).to include("Log in", "Forgot your password?")
    expect(response.body).not_to include("Sign up")
  end

  it "shows a flash message after a failed sign-in" do
    user = create(:user)
    post user_session_path, params: { user: { email: user.email, password: "wrong" } }
    expect(response.body).to include('class="flash flash-alert"')
  end

  it "signs out and returns to the landing page with a notice" do
    sign_in create(:user)
    delete destroy_user_session_path
    expect(response).to redirect_to(root_path)
    follow_redirect!
    expect(response.body).to include('class="flash flash-notice"', "Sign in")
  end
end
