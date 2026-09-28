require "uri"

module OAuth
  # The hub's rules for a registered client, mixed into Doorkeeper::Application
  # from config/initializers/doorkeeper.rb (app/models stays Doorkeeper-free;
  # see docs/ARCHITECTURE.md §4). Doorkeeper's own validations (uid, secret
  # presence for confidential clients, configured scopes, URI well-formedness)
  # still run; these are the stricter policy on top.
  #
  # `client_type` is the source of truth; Doorkeeper's `confidential` flag must
  # agree with it (OAuth::Clients sets both) and a public client must have no
  # secret at all — it authenticates with PKCE only (enforced at authorize by
  # TASK-017).
  #
  # Redirect URI allow-list (OAuth 2.1 / RFC 8252):
  #   - absolute, no fragment, no userinfo;
  #   - https for any host;
  #   - http only for loopback hosts (localhost, 127.0.0.1, ::1), where the
  #     port is ignored at authorization time (RFC 8252 §7.3);
  #   - a private-use scheme (e.g. com.example.app:/callback) only for public
  #     clients — native apps and MCP clients; never for confidential ones;
  #   - the out-of-band URN and any other bare `scheme:opaque` form are refused.
  #
  # Approval state machine: pending → approved, pending → revoked,
  # approved → revoked. Revoked is final.
  module ClientRules
    extend ActiveSupport::Concern

    CLIENT_TYPES = %w[confidential public].freeze
    APPROVAL_STATES = %w[pending approved revoked].freeze
    APPROVAL_TRANSITIONS = {
      "pending" => %w[approved revoked],
      "approved" => %w[revoked],
      "revoked" => []
    }.freeze
    REGISTRATION_SOURCES = %w[admin dynamic].freeze
    LOOPBACK_HOSTS = %w[localhost 127.0.0.1 ::1 [::1]].freeze
    OOB_URI = "urn:ietf:wg:oauth:2.0:oob".freeze

    included do
      belongs_to :owner, class_name: "User", optional: true

      validates :client_type, inclusion: { in: CLIENT_TYPES }
      validates :approval_state, inclusion: { in: APPROVAL_STATES }
      validates :registered_via, inclusion: { in: REGISTRATION_SOURCES }
      validate :confidential_matches_client_type
      validate :public_client_has_no_secret
      validate :redirect_uris_allowed
      validate :scopes_in_catalogue
      validate :approval_transition_allowed, on: :update
    end

    # @return [Boolean] whether the client is a public (PKCE-only) client.
    def public_client?
      client_type == "public"
    end

    # @return [Boolean] whether authorize/token may serve this client.
    def usable?
      approval_state == "approved"
    end

    # @param uri [URI::Generic]
    # @return [Boolean]
    def self.loopback?(uri)
      LOOPBACK_HOSTS.include?(uri.host.to_s.downcase)
    end

    # @param value [String] one redirect URI
    # @param public_client [Boolean] whether private-use schemes are acceptable
    # @return [Symbol, nil] the reason the URI is refused, nil when allowed
    def self.redirect_uri_problem(value, public_client:)
      return :oob_uri if value == OOB_URI

      uri = URI.parse(value)
      return :relative_uri if uri.scheme.blank?
      return :fragment_present if uri.fragment
      return :userinfo_present if uri.userinfo

      case uri.scheme.downcase
      when "https" then :missing_host if uri.host.blank?
      when "http" then :insecure_uri unless loopback?(uri)
      else
        return :opaque_uri if uri.opaque

        :private_scheme_for_confidential_client unless public_client
      end
    rescue URI::InvalidURIError
      :invalid_uri
    end

    private

    def confidential_matches_client_type
      return if client_type.blank? || confidential == !public_client?

      errors.add(:confidential, "must be #{!public_client?} for a #{client_type} client")
    end

    def public_client_has_no_secret
      return unless public_client? && secret.present?

      errors.add(:secret, "must be empty for a public client")
    end

    def redirect_uris_allowed
      redirect_uri.to_s.split.each do |value|
        problem = ClientRules.redirect_uri_problem(value, public_client: public_client?)
        errors.add(:redirect_uri, "#{value}: #{problem.to_s.humanize(capitalize: false)}") if problem
      end
    end

    def scopes_in_catalogue
      unknown = scopes.to_a - OAuth::Scopes.names
      errors.add(:scopes, "not in the catalogue: #{unknown.join(', ')}") if unknown.any?
    end

    def approval_transition_allowed
      return unless approval_state_changed?

      from = approval_state_was
      return if APPROVAL_TRANSITIONS.fetch(from, []).include?(approval_state)

      errors.add(:approval_state, "cannot change from #{from} to #{approval_state}")
    end
  end
end
