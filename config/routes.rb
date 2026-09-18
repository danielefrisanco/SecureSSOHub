Rails.application.routes.draw do
  # JWKS is served by the hub (cache headers, rotation) at both the standard
  # path and the one the OIDC engine advertises; defined first so it shadows
  # the engine's own keys action.
  get "/.well-known/jwks.json", to: "well_known#jwks", as: :jwks
  get "/oauth/discovery/keys", to: "well_known#jwks"

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
