Rails.application.routes.draw do
  # JWKS and the discovery documents are served by the hub (cache headers,
  # rotation, URLs from HUB_ISSUER); defined first so they shadow the OIDC
  # engine's own keys/provider actions at the same paths.
  get "/.well-known/jwks.json", to: "well_known#jwks", as: :jwks
  get "/oauth/discovery/keys", to: "well_known#jwks"
  get "/.well-known/openid-configuration", to: "well_known#openid_configuration", as: :openid_configuration
  get "/.well-known/oauth-authorization-server", to: "well_known#oauth_authorization_server",
                                                 as: :oauth_authorization_server

  # RFC 7591 dynamic client registration (Doorkeeper has none).
  post "/oauth/register", to: "client_registrations#create", as: :oauth_registration

  use_doorkeeper_openid_connect
  use_doorkeeper
  devise_for :users

  # Bearer-token API, guarded by rack-jwt-verifier (config/initializers/rack_jwt_verifier.rb).
  namespace :api do
    namespace :v1 do
      get "userinfo", to: "userinfo#show"
    end
  end
  # Define your application routes per the DSL in https://guides.rubyonrails.org/routing.html

  # Reveal health status on /up that returns 200 if the app boots with no exceptions, otherwise 500.
  # Can be used by load balancers and uptime monitors to verify that the app is live.
  get "up" => "rails/health#show", as: :rails_health_check

  # Root route (for basic health check/landing page)
  root "home#index"
end
