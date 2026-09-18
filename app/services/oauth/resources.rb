require "uri"

module OAuth
  # Resource indicators (RFC 8707): the identifiers a client may name in the
  # `resource` parameter of an authorization or token request. A resource
  # ends up as the `aud` of the access token (OAuth::TokenPayload); when a request names
  # none, `aud` defaults to the client's own client_id.
  #
  # The known resources are the hub's own: its API and the MCP endpoint, both
  # rooted at the issuer URL. Per-client registered resources are not a thing
  # yet — `known` already takes the client so they can be added without
  # touching callers.
  module Resources
    module_function

    # Canonical URL of the hub (HUB_ISSUER), loaded at boot by the Doorkeeper
    # initializer.
    #
    # @return [String]
    def issuer
      Rails.configuration.x.oauth.issuer
    end

    # @return [String] identifier of the hub's own API.
    def hub_api
      "#{issuer}/api"
    end

    # @return [String] identifier of the hub's MCP endpoint.
    def hub_mcp
      "#{issuer}/mcp"
    end

    # @param client_uid [String, nil] the requesting client (reserved for
    #   per-client resources)
    # @return [Array<String>] every resource identifier a client may request.
    def known(client_uid: nil) # rubocop:disable Lint/UnusedMethodArgument
      [hub_api, hub_mcp]
    end

    # RFC 8707 §2: an absolute URI without fragment, matched exactly against
    # the known list.
    #
    # @param value [String]
    # @param client_uid [String, nil]
    # @return [Boolean]
    def known?(value, client_uid: nil)
      uri = URI.parse(value.to_s)
      uri.absolute? && uri.fragment.nil? && known(client_uid: client_uid).include?(value)
    rescue URI::InvalidURIError
      false
    end
  end
end
