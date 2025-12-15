# # Inizializzatore per configurare l'applicazione Rails come un SSO Provider (Hub).
# Rails.application.config.middleware.use OmniAuth::Builder do
#   provider :sso_provider, 
#     # Chiave di identificazione pubblica per questo SSO Hub. 
#     # Le App Client la useranno per identificarsi.
#     client_id: Rails.application.credentials.sso_hub_client_id, 

#     # Chiave segreta che solo l'Hub SSO conosce. 
#     # Sarà usata per firmare i JWT in modo sicuro.
#     client_secret: Rails.application.credentials.sso_hub_client_secret, 

#     # Metodo per trovare l'utente a partire dall'identificativo nel JWT.
#     # Assumiamo che l'utente sia identificato tramite 'email'
#     find_user: lambda { |identifier| 
#       User.find_by(email: identifier) 
#     },

#     # Questo è il blocco più importante: definisce i dati che verranno inclusi nel JWT.
#     # Questi dati saranno inviati all'App Client.
#     # Includeremo l'email e un sso_id unico.
#     user_info_mapper: lambda { |user|
#       {
#         'email' => user.email,
#         'sso_id' => user.sso_id # Assumiamo che il modello User abbia un campo sso_id
#       }
#     },

#     # Definisce le applicazioni client autorizzate a usare questo SSO Hub.
#     # DOVRAI AGGIUNGERE LA TUA VUE.JS APP QUI quando avremo i suoi dettagli.
#     authorized_clients: [
#       {
#         # Questo è un esempio per il tuo client Vue.js:
#         id: "securee2e-vue-client",
#         redirect_uri: "http://localhost:8080/auth/sso/callback" # URL di callback del tuo client
#       }
#     ]
# end
# Require the custom OmniAuth strategy gem explicitly
require 'omniauth/sso_provider'

# OmniAuth configuration for the Secure SSO Hub client
Rails.application.config.middleware.use OmniAuth::Builder do
  # The provider name should be the symbol version of the strategy constant
  # We are explicitly requiring the gem above.
  # Note: The gem 'omniauth-ssoprovider' likely exposes the strategy as OmniAuth::Strategies::SSOProvider
  provider :sso_provider, 
    # Use environment variables or Rails credentials for production secrets
    ENV.fetch('SSO_HUB_CLIENT_ID'), 
    ENV.fetch('SSO_HUB_CLIENT_SECRET'),
    
    # Optional configurations for OmniAuth::Strategies::SsoProvider 
    # (These depend on the actual implementation of the gem, but are standard)
    client_options: {
      site: ENV.fetch('SSO_HUB_URL') { 'http://localhost:3000' }, # The base URL of the Hub (your current Rails app)
      authorize_url: '/oauth/authorize',
      token_url: '/oauth/token'
    }
    
    # Optional scopes array if the hub supports scoping
    # scope: 'profile email' 
end

# To handle Devise integration, you must ensure that the OmniAuth Callbacks Controller
# is set up to handle the successful authentication from the provider.