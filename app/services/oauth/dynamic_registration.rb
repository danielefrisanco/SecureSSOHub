require "json"
require "uri"

module OAuth
  # POST /oauth/register — RFC 7591 dynamic client registration (TASK-025).
  # Turns a client's JSON metadata into one call to
  # OAuth::Clients.register_dynamic and builds the RFC 7591 response; the
  # policy (approval | open | closed) is OAuth::RegistrationPolicy and the
  # endpoint ClientRegistrationsController.
  #
  # Accepted metadata — anything else is ignored:
  #   client_name                 required
  #   redirect_uris               required; the OAuth::ClientRules allow-list
  #   token_endpoint_auth_method  `none` → public (PKCE) client;
  #                               `client_secret_basic` (default, RFC 7591 §2)
  #                               or `client_secret_post` → confidential
  #   grant_types                 authorization_code (default), refresh_token;
  #                               never client_credentials — machine access is
  #                               an administrator's decision
  #   response_types              ["code"] (default)
  #   scope                       user-consentable scopes (default `openid`);
  #                               never admin or machine ones
  #   software_id, software_version, client_uri, logo_uri (both https),
  #   contacts (array of strings)
  #
  # Refusals: 400 `invalid_redirect_uri` for a redirect URI problem,
  # 400 `invalid_client_metadata` for everything else (RFC 7591 §3.2.2) —
  # including a duplicate (same client_name and redirect_uris registered in
  # the last 24 hours) and a confidential client under the open policy. The
  # duplicate check is check-then-insert without a lock, so a burst of
  # concurrent requests can slip a few through; the per-address rate limit
  # (ClientRegistrationsController, TASK-028) bounds that burst. Every
  # registration is logged at info with its client_id and source address.
  class DynamicRegistration
    Result = Struct.new(:status, :body, keyword_init: true)

    class Refused < StandardError
      attr_reader :code

      def initialize(code, description)
        @code = code
        super(description)
      end
    end

    AUTH_METHODS = { "none" => "public", "client_secret_basic" => "confidential",
                     "client_secret_post" => "confidential" }.freeze
    GRANT_TYPES = %w[authorization_code refresh_token].freeze
    RESPONSE_TYPES = %w[code].freeze
    DUPLICATE_WINDOW = 24.hours
    MAX_STRING = 255
    APPROVAL_MESSAGES = {
      "pending" => "Registration received. An administrator must approve this client before it can sign users in.",
      "approved" => "The client is registered and can be used now."
    }.freeze

    # @param raw_body [String] the request body (JSON)
    # @param ip [String] the requester's address
    # @return [Result]
    def self.call(raw_body, ip:)
      new(raw_body, ip).call
    end

    def initialize(raw_body, ip)
      @raw_body = raw_body.to_s
      @ip = ip
    end

    def call
      request = validated_request
      registration = register(request)
      log(registration.client)
      Result.new(status: :created, body: response_body(registration, request))
    rescue Refused => e
      error(e.code, e.message)
    rescue Clients::Invalid => e
      error(e.attributes.include?(:redirect_uri) ? "invalid_redirect_uri" : "invalid_client_metadata", e.message)
    end

    private

    attr_reader :raw_body, :ip

    def register(request)
      refuse_duplicate(request)
      Clients.register_dynamic(
        name: request[:client_name], redirect_uris: request[:redirect_uris], client_type: request[:client_type],
        scopes: request[:scopes], policy: RegistrationPolicy.current, metadata: request[:metadata],
        registration_ip: ip
      )
    end

    # @return [Hash] the validated request, keyed for register_dynamic and the response
    def validated_request
      body = parse
      auth_method = string(body, "token_endpoint_auth_method") || "client_secret_basic"
      {
        client_name: string(body, "client_name") || refuse("client_name is required"),
        redirect_uris: redirect_uris(body),
        token_endpoint_auth_method: auth_method,
        client_type: client_type(auth_method),
        grant_types: grant_types(body),
        response_types: response_types(body),
        scopes: scopes(body),
        metadata: optional_metadata(body)
      }
    end

    def parse
      body = JSON.parse(raw_body)
      body.is_a?(Hash) ? body : refuse("the request body must be a JSON object")
    rescue JSON::ParserError
      refuse("the request body must be a JSON object")
    end

    def redirect_uris(body)
      uris = body["redirect_uris"]
      return uris if uris.is_a?(Array) && uris.any? && uris.all? { |uri| uri.is_a?(String) && uri.present? }

      refuse("redirect_uris must be a non-empty array of URIs", code: "invalid_redirect_uri")
    end

    def client_type(auth_method)
      type = AUTH_METHODS.fetch(auth_method) do
        refuse("token_endpoint_auth_method must be one of #{AUTH_METHODS.keys.join(', ')}")
      end
      if type == "confidential" && RegistrationPolicy.current == :open
        refuse("open registration accepts public clients only (token_endpoint_auth_method none)")
      end
      type
    end

    def grant_types(body)
      types = string_array(body, "grant_types") || ["authorization_code"]
      unless types.include?("authorization_code") && (types - GRANT_TYPES).empty?
        refuse("grant_types must include authorization_code and may add refresh_token")
      end
      types.uniq
    end

    def response_types(body)
      types = string_array(body, "response_types") || RESPONSE_TYPES
      types.uniq == RESPONSE_TYPES ? RESPONSE_TYPES : refuse("response_types must be [\"code\"]")
    end

    def scopes(body)
      scope = string(body, "scope", max: 1000)
      scope ? scope.split : Scopes.names.select { |name| Scopes.default?(name) }
    end

    def optional_metadata(body)
      fields = {
        software_id: string(body, "software_id"),
        software_version: string(body, "software_version"),
        client_uri: https_uri(body, "client_uri"),
        logo_uri: https_uri(body, "logo_uri"),
        contacts: string_array(body, "contacts")
      }
      fields.compact
    end

    def https_uri(body, field)
      value = string(body, field, max: 2000)
      return if value.nil?

      uri = URI.parse(value)
      return value if uri.is_a?(URI::HTTPS) && uri.host.present?

      refuse("#{field} must be an https URL")
    rescue URI::InvalidURIError
      refuse("#{field} must be an https URL")
    end

    # @return [String, nil] nil when absent
    def string(body, field, max: MAX_STRING)
      value = body[field]
      return if value.nil?
      return value.strip if value.is_a?(String) && value.strip.present? && value.length <= max

      refuse("#{field} must be a non-empty string of at most #{max} characters")
    end

    # @return [Array<String>, nil] nil when absent
    def string_array(body, field)
      value = body[field]
      return if value.nil?
      return value if value.is_a?(Array) && value.all? { |item| item.is_a?(String) && item.length <= MAX_STRING }

      refuse("#{field} must be an array of strings")
    end

    def refuse_duplicate(request)
      return unless Clients.dynamic_duplicate?(name: request[:client_name], redirect_uris: request[:redirect_uris],
                                               since: DUPLICATE_WINDOW.ago)

      refuse("a client with this client_name and these redirect_uris was registered in the last 24 hours")
    end

    def refuse(description, code: "invalid_client_metadata")
      raise Refused.new(code, description)
    end

    def response_body(registration, request)
      client = registration.client
      body = {
        client_id: client.uid,
        client_id_issued_at: client.created_at.to_i,
        client_name: client.name,
        redirect_uris: client.redirect_uris,
        token_endpoint_auth_method: request[:token_endpoint_auth_method],
        grant_types: request[:grant_types],
        response_types: request[:response_types],
        scope: client.scopes.join(" "),
        **request[:metadata],
        approval_state: client.approval_state,
        approval_message: APPROVAL_MESSAGES.fetch(client.approval_state)
      }
      return body unless registration.secret

      { client_id: client.uid, client_secret: registration.secret, client_secret_expires_at: 0 }.merge(body)
    end

    def error(code, description)
      Result.new(status: :bad_request, body: { error: code, error_description: description })
    end

    def log(client)
      Rails.logger.info("[oauth.register] client_id=#{client.uid} ip=#{ip} policy=#{RegistrationPolicy.current} " \
                        "approval_state=#{client.approval_state}")
    end
  end
end
