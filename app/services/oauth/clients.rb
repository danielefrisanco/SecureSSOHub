module OAuth
  # The client registry. This module (and its siblings in app/services/oauth)
  # is the only place that may touch Doorkeeper models — controllers, views,
  # jobs and MCP tools go through it so the authorization-server core can be
  # replaced (docs/ARCHITECTURE.md §4). The validations live in
  # OAuth::ClientRules.
  #
  # Every mutating call takes `by:` (a User) and raises Forbidden unless that
  # user is an administrator; owner-based permissions come with the account UI.
  # The one exception is `register_dynamic`, reserved for the unauthenticated
  # RFC 7591 endpoint (TASK-025).
  #
  # Client secrets are hashed at rest: `create`, `register_dynamic` and
  # `rotate_secret` return the plain secret exactly once, in a Registration.
  # Rotating a secret does not touch the tokens already issued to the client —
  # they stay valid until they expire or are revoked; only new token requests
  # must present the new secret.
  #
  # No audit log yet (T25) — every change goes through here so it can hook in.
  module Clients
    Client = Struct.new(:uid, :name, :redirect_uris, :scopes, :client_type, :confidential, :approval_state,
                        :registered_via, :owner_id, :software_id, :software_version, :client_uri, :logo_uri,
                        :contacts, :last_used_at, :created_at, :updated_at, keyword_init: true) do
      def public?
        client_type == "public"
      end

      def usable?
        approval_state == "approved"
      end
    end

    # A newly created or rotated client together with its one-time plain secret
    # (nil for public clients).
    Registration = Struct.new(:client, :secret, keyword_init: true)

    class Error < StandardError; end
    class Forbidden < Error; end
    class NotFound < Error; end

    # The record failed OAuth::ClientRules / Doorkeeper validation.
    class Invalid < Error
      attr_reader :messages

      def initialize(messages)
        @messages = Array(messages)
        super(@messages.join("; "))
      end
    end

    # The approval-state change is not one the state machine allows.
    class InvalidTransition < Invalid; end

    METADATA_FIELDS = %i[software_id software_version client_uri logo_uri contacts].freeze
    REGISTRATION_POLICIES = %i[approval open].freeze

    module_function

    # @param state [String, Symbol, nil] filter on approval_state.
    # @return [Array<Client>] registered clients, newest first.
    def list(state: nil)
      scope = Doorkeeper::Application.order(created_at: :desc)
      scope = scope.where(approval_state: state.to_s) if state
      scope.map { |app| wrap(app) }
    end

    # @param uid [String] the public client_id.
    # @return [Client, nil]
    def find(uid)
      app = Doorkeeper::Application.find_by(uid: uid)
      app && wrap(app)
    end

    # @return [Boolean] whether the client exists and is approved.
    def usable?(uid)
      Doorkeeper::Application.exists?(uid: uid, approval_state: "approved")
    end

    # Registers a client on behalf of an administrator.
    #
    # @param name [String]
    # @param redirect_uris [Array<String>]
    # @param client_type [String, Symbol] confidential | public
    # @param scopes [Array<String>]
    # @param by [User] the acting administrator
    # @param owner [User, nil] defaults to the actor
    # @param registered_via [Symbol] admin | dynamic
    # @param metadata [Hash] RFC 7591 fields (METADATA_FIELDS)
    # @return [Registration] the client and its one-time secret
    def create(name:, redirect_uris:, client_type:, scopes:, by:, owner: by, registered_via: :admin, metadata: {})
      authorize!(by)
      persist(attributes(name, redirect_uris, client_type, scopes, metadata).merge(
                owner: owner, registered_via: registered_via.to_s, approval_state: "approved"
              ))
    end

    # The only entry point without an administrator: an unknown party asks to
    # be registered (RFC 7591). The client is pending until an admin approves
    # it (policy :approval) or usable at once (policy :open); admin and machine
    # scopes are never granted this way.
    #
    # @param policy [Symbol] :approval | :open
    # @return [Registration]
    def register_dynamic(name:, redirect_uris:, client_type:, scopes:, policy:, metadata: {})
      unless REGISTRATION_POLICIES.include?(policy)
        raise ArgumentError, "policy must be one of #{REGISTRATION_POLICIES.inspect}"
      end

      denied = Array(scopes).map(&:to_s) - OAuth::Scopes.dynamic_registration_names
      raise Invalid, "scopes not available to dynamically registered clients: #{denied.join(', ')}" if denied.any?

      persist(attributes(name, redirect_uris, client_type, scopes, metadata).merge(
                owner: nil, registered_via: "dynamic",
                approval_state: policy == :open ? "approved" : "pending"
              ))
    end

    # Changes name, redirect URIs, scopes and/or metadata. The client type is
    # fixed at registration (switching it would mean adding or dropping a
    # secret); register a new client instead.
    #
    # @return [Client]
    def update(uid, by:, name: nil, redirect_uris: nil, scopes: nil, metadata: nil)
      authorize!(by)
      app = fetch(uid)
      changes = {}
      changes[:name] = name unless name.nil?
      changes[:redirect_uri] = Array(redirect_uris) unless redirect_uris.nil?
      changes[:scopes] = Array(scopes).map(&:to_s) unless scopes.nil?
      changes.merge!(metadata.to_h.symbolize_keys.slice(*METADATA_FIELDS)) unless metadata.nil?
      app.assign_attributes(changes)
      save!(app)
      wrap(app)
    end

    # Issues a new secret; the old one stops working immediately, issued
    # tokens are unaffected.
    #
    # @return [Registration] with the new one-time secret
    def rotate_secret(uid, by:)
      authorize!(by)
      app = fetch(uid)
      raise Invalid, "a public client has no secret to rotate" if app.public_client?

      app.renew_secret
      save!(app)
      Registration.new(client: wrap(app), secret: app.plaintext_secret)
    end

    # @return [Client]
    def approve(uid, by:)
      transition(uid, to: "approved", by: by)
    end

    # Blocks the client (final) and revokes every token and grant it holds.
    #
    # @return [Client]
    def revoke(uid, by:)
      client = transition(uid, to: "revoked", by: by)
      OAuth::Tokens.revoke_all(client_uid: uid)
      client
    end

    def authorize!(by)
      return if by.is_a?(User) && by.is_admin

      raise Forbidden, "only administrators may manage clients"
    end
    private_class_method :authorize!

    def fetch(uid)
      Doorkeeper::Application.find_by(uid: uid) || raise(NotFound, "no client with client_id #{uid}")
    end
    private_class_method :fetch

    def attributes(name, redirect_uris, client_type, scopes, metadata)
      type = client_type.to_s
      {
        name: name,
        redirect_uri: Array(redirect_uris),
        scopes: Array(scopes).map(&:to_s),
        client_type: type,
        confidential: type != "public",
        **metadata.to_h.symbolize_keys.slice(*METADATA_FIELDS)
      }
    end
    private_class_method :attributes

    def persist(attrs)
      app = Doorkeeper::Application.new(attrs)
      save!(app)
      Registration.new(client: wrap(app), secret: app.public_client? ? nil : app.plaintext_secret)
    end
    private_class_method :persist

    def transition(uid, to:, by:)
      authorize!(by)
      app = fetch(uid)
      from = app.approval_state
      unless OAuth::ClientRules::APPROVAL_TRANSITIONS.fetch(from).include?(to)
        raise InvalidTransition, "client is #{from}; cannot make it #{to}"
      end

      app.approval_state = to
      save!(app)
      wrap(app)
    end
    private_class_method :transition

    def save!(app)
      raise Invalid, app.errors.full_messages unless app.save

      app
    end
    private_class_method :save!

    def wrap(app)
      Client.new(
        uid: app.uid,
        name: app.name,
        redirect_uris: app.redirect_uri.to_s.split,
        scopes: app.scopes.to_a,
        client_type: app.client_type,
        confidential: app.confidential?,
        approval_state: app.approval_state,
        registered_via: app.registered_via,
        owner_id: app.owner_id,
        software_id: app.software_id,
        software_version: app.software_version,
        client_uri: app.client_uri,
        logo_uri: app.logo_uri,
        contacts: app.contacts,
        last_used_at: app.last_used_at,
        created_at: app.created_at,
        updated_at: app.updated_at
      )
    end
    private_class_method :wrap
  end
end
