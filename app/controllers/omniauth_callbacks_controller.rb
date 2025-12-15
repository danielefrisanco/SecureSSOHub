class OmniauthCallbacksController < ApplicationController
  # This controller handles the final steps of the SSO handshake,
  # specifically for the 'sso_provider' strategy.

  # Since OmniAuth handles the initial routing, we must ensure Devise knows 
  # which authentication method to use (in this case, our own).
  
  # This action is invoked when the user has already successfully authenticated 
  # via Devise *OR* they are redirected after Devise successfully logs them in.
  def sso_provider_callback
    # 1. Check if the user is authenticated via Devise.
    unless current_user
      # This scenario should rarely happen if the initial '/auth/:provider' logic is correct,
      # but it's a safety net. If not logged in, force a redirect to login.
      redirect_to new_user_session_url, alert: t('devise.failure.unauthenticated')
      return
    end

    # 2. The omniauth-ssoprovider strategy places the necessary data in request.env['omniauth.auth'].
    auth_data = request.env['omniauth.auth']

    # 3. Retrieve the redirect_uri that the client provided (where to send the user back)
    redirect_uri = auth_data.extra.return_to

    # 4. Generate the JWT (using the method defined in app/models/user.rb)
    # The JWT is now signed with the Hub's secret.
    token = current_user.to_jwt 

    # 5. Build the final redirect URL to the client.
    # We pass the JWT token and the client_id as URL parameters.
    # The client will use this token to establish its own local session.
    final_redirect_url = "#{redirect_uri}?token=#{token}&client_id=#{auth_data.uid}"
    
    # 6. Redirect the user back to the client application.
    redirect_to final_redirect_url, allow_other_host: true
  rescue StandardError => e
    Rails.logger.error "SSO Callback Error: #{e.message}"
    # Handle error gracefully (e.g., redirect to the root with an error message)
    redirect_to root_url, alert: t('sso.error.general', default: "SSO authentication failed.")
  end
  
  # This action is necessary for OmniAuth to correctly trigger the Devise sign_in flow 
  # when an unauthenticated user hits the /auth/:provider path.
  def passthru
    render file: "#{Rails.root}/public/404.html", status: 404, layout: false
  end
end
