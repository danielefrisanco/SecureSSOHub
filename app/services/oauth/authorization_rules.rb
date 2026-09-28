module OAuth
  # The hub's rules for an authorization request, prepended into
  # Doorkeeper::OAuth::PreAuthorization from config/initializers/doorkeeper.rb
  # (controllers never name Doorkeeper; see docs/ARCHITECTURE.md §4).
  # Doorkeeper's own checks (client, redirect_uri exact match, response_type,
  # scopes ⊆ client scopes ⊆ catalogue) still run; these are the stricter
  # policy on top:
  #
  #   - redirect_uri (OAuth 2.1 §4.1.1): exact string match against the
  #     registered list — Doorkeeper alone tolerates extra query parameters.
  #     Only the port of a loopback URI may differ (RFC 8252 §7.3).
  #   - PKCE (RFC 7636): a public client must send a `code_challenge` with
  #     `code_challenge_method=S256`; a confidential client may. `plain` is
  #     never accepted. Any problem is an RFC 6749 `invalid_request` with a
  #     reason, not Doorkeeper's non-standard `invalid_code_challenge_method`.
  #   - Resource indicator (RFC 8707): an optional `resource` must be one of
  #     OAuth::Resources.known, otherwise `invalid_target`. It is persisted on
  #     the grant (Doorkeeper custom_access_token_attributes) and copied to
  #     the token, where OAuth::TokenPayload turns it into `aud`.
  #   - Admin scopes (`admin` flag in the catalogue): only an administrator
  #     may consent to them; anyone else gets `invalid_scope`.
  module AuthorizationRules
    # RFC 7636 §4.2: 43 to 128 unreserved characters.
    CODE_CHALLENGE_FORMAT = /\A[A-Za-z0-9\-._~]{43,128}\z/
    CODE_CHALLENGE_METHOD = "S256".freeze

    # RFC 8707 §2 error; Doorkeeper names the response after the class.
    class InvalidTarget < Doorkeeper::Errors::BaseResponseError; end

    # Registered last on purpose: the redirect_uri is validated by then, so
    # the error can be sent back to the client.
    def self.prepended(base)
      base.validate :resource, error: InvalidTarget
    end

    attr_reader :resource

    def initialize(server, parameters = {}, resource_owner = nil)
      super
      @resource = parameters[:resource]
    end

    private

    def validate_redirect_uri
      super && redirect_uri_registered?
    end

    def redirect_uri_registered?
      requested = URI.parse(redirect_uri)
      client.redirect_uri.to_s.split.any? do |registered|
        redirect_uri == registered || loopback_match?(requested, URI.parse(registered))
      end
    rescue URI::InvalidURIError
      false
    end

    def loopback_match?(requested, registered)
      return false unless OAuth::ClientRules.loopback?(requested) && OAuth::ClientRules.loopback?(registered)

      [requested, registered].map { |uri| uri.dup.tap { |copy| copy.port = nil }.to_s }.uniq.one?
    end

    # Doorkeeper calls `validate_<attribute>` for each registered validation,
    # so these two cannot end in `?`.
    def validate_code_challenge # rubocop:disable Naming/PredicateMethod
      reason = code_challenge_problem
      @invalid_request_reason = reason if reason
      reason.nil?
    end

    # @return [Symbol, nil] the invalid_request reason, nil when acceptable
    def code_challenge_problem
      if code_challenge.blank?
        :invalid_code_challenge unless client.confidential
      elsif !CODE_CHALLENGE_FORMAT.match?(code_challenge)
        :malformed_code_challenge
      elsif code_challenge_method != CODE_CHALLENGE_METHOD
        :invalid_code_challenge_method
      end
    end

    def validate_resource # rubocop:disable Naming/PredicateMethod
      resource.nil? || OAuth::Resources.known?(resource, client_uid: client.uid)
    end

    def validate_scopes
      super && admin_scopes_permitted?
    end

    # A request without a signed-in owner (the disabled-account guard) is
    # treated as a non-admin: the safe default.
    def admin_scopes_permitted?
      return true if resource_owner&.is_admin

      scopes.none? { |scope| OAuth::Scopes.admin?(scope) }
    end
  end
end
