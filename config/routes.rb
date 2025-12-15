Rails.application.routes.draw do
  devise_for :users
  # Define your application routes per the DSL in https://guides.rubyonrails.org/routing.html

  # Reveal health status on /up that returns 200 if the app boots with no exceptions, otherwise 500.
  # Can be used by load balancers and uptime monitors to verify that the app is live.
  get "up" => "rails/health#show", as: :rails_health_check

  # Defines the root path route ("/")
  # root "posts#index"
   
  # === SSO PROVIDER ROUTES ===
  
  # 1. The main OmniAuth entry point (where the client redirects the user to start SSO)
  # This path is handled automatically by OmniAuth middleware:
  # It checks if the user is logged in via Devise.
  # If logged in, it proceeds to the SSO callback (path 2).
  # If NOT logged in, it redirects the user to the Devise sign_in page.
  get '/auth/:provider', to: 'omniauth_callbacks#passthru', as: 'omniauth_authorize'

  # 2. The OmniAuth callback (where the JWT is generated and returned to the client)
  # This path will be handled by a custom action in a controller.
  get '/auth/:provider/callback', to: 'omniauth_callbacks#sso_provider_callback'
  
  # Root route (for basic health check/landing page)
  root "home#index"
end
