module OAuth
  # The scope catalogue (config/oauth_scopes.yml) as the application sees it.
  # Loaded at boot by the Doorkeeper initializer into config.x.oauth.scopes;
  # the consent page, userinfo and MCP read it through here.
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

    # @return [Boolean] whether the scope is in the catalogue.
    def known?(name)
      catalogue.key?(name.to_s)
    end

    # What the consent page shows the user for a scope.
    #
    # @param name [String, Symbol]
    # @return [String, nil] nil for a scope outside the catalogue
    def description(name)
      catalogue.dig(name.to_s, :description)
    end

    def admin?(name)
      flag?(name, :admin)
    end

    def default?(name)
      flag?(name, :default)
    end

    def machine?(name)
      flag?(name, :machine)
    end

    # Scopes only an administrator may consent to.
    #
    # @return [Array<String>]
    def admin_names
      catalogue.select { |_, attrs| attrs[:admin] }.keys
    end

    # Scopes a client registered without an admin may hold: nothing marked
    # admin or machine.
    #
    # @return [Array<String>]
    def dynamic_registration_names
      catalogue.reject { |_, attrs| attrs[:admin] || attrs[:machine] }.keys
    end

    def flag?(name, flag)
      catalogue.dig(name.to_s, flag) == true
    end
    private_class_method :flag?
  end
end
