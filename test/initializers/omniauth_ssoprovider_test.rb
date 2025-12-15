require 'test_helper'

class OmniAuthSSOProviderInitializationTest < ActiveSupport::TestCase
  
  # Verifica che la configurazione OmniAuth per l'SSO Provider esista.
  test "omniauth sso provider middleware is configured" do
    # OmniAuth usa un "Rack::Builder" (OmniAuth::Builder) per registrare i provider.
    # Verifichiamo che un provider con il nome 'sso_provider' sia stato caricato nella middleware stack.
    middleware_stack = Rails.application.config.middleware
    
    # Cerchiamo la classe OmniAuth::Strategies::SSOProvider (il nome interno della gemma)
    sso_provider_class = OmniAuth::Strategies::SSOProvider 

    # Controlliamo se la nostra middleware stack include un provider con il nome 'sso_provider'
    assert middleware_stack.any? { |middleware| 
      middleware.name == sso_provider_class.name
    }, "OmniAuth SSO Provider was not found in the middleware stack."
  end
  
  # Aggiungeremo qui i test per la generazione del JWT e il find_user man mano che implementiamo la logica.
end