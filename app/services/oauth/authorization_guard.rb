module OAuth
  # Hub-level guard on the authorization endpoint, prepended into
  # Doorkeeper::AuthorizationsController from config/initializers/doorkeeper.rb.
  #
  # A disabled account (users.disabled_at) may still hold a Devise session;
  # it must not authorize anything. The session is closed and the client is
  # told `access_denied` (RFC 6749 §4.1.2.1): redirected when the request
  # itself validates, rendered otherwise — never to an unvalidated
  # redirect_uri.
  module AuthorizationGuard
    private

    def authenticate_resource_owner!
      user = current_user
      return super unless user&.disabled_at

      sign_out(user)
      deny_disabled_user
    end

    def deny_disabled_user
      @pre_auth = Doorkeeper::OAuth::PreAuthorization.new(Doorkeeper.configuration, pre_auth_params, nil)
      pre_auth.error = Doorkeeper::Errors::AccessDenied if pre_auth.authorizable?
      error_response = pre_auth.error_response

      if error_response.redirectable?
        redirect_or_render(error_response)
      else
        render :error, locals: { error_response: error_response }, status: error_response.status
      end
    end
  end
end
