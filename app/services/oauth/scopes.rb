module OAuth
  # The scope catalogue (config/oauth_scopes.yml) as the application sees it.
  # Loaded at boot by the Doorkeeper initializer into config.x.oauth.scopes;
  # consent page, userinfo and MCP (TASK-018+) read it through here.
  #
  # Flags per scope: `default` (implied when a client asks for none), `admin`
  # (only administrators may grant it), `machine` (for resource servers, never
  # for a user-facing client).
  module Scopes
    module_function

    # @return [Hash{String => Hash}] scope name → attributes (symbol keys).
    def catalogue
      Rails.configuration.x.oauth.scopes.to_h.transform_keys(&:to_s)
    end

    # @return [Array<String>] every scope name.
    def names
      catalogue.keys
    end

    # Scopes a client registered without an admin may hold: nothing marked
    # admin or machine.
    #
    # @return [Array<String>]
    def dynamic_registration_names
      catalogue.reject { |_, attrs| attrs[:admin] || attrs[:machine] }.keys
    end
  end
end
