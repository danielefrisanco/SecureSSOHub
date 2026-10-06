module OAuth
  # Issued access/refresh tokens as the application sees them (the payload
  # itself is OAuth::TokenPayload; `jti` is the claim of the same name, put on
  # the row by OAuth::TokenRecord). An access token and the refresh token
  # issued with it share one row, so revoking either revokes both.
  #
  # Token family: every access/refresh token remembers the authorization code
  # it descends from (`access_grant_id`, copied across refresh rotations by
  # OAuth::TokenRules). A replayed code revokes its descendants; a replayed
  # refresh token revokes everything the client holds for that user; a
  # revoked token takes its family with it (#revoke, the revocation endpoint).
  #
  # Revocation reaches the hub's own API, introspection callers and the
  # refresh flow at once; a resource server verifying a JWT offline keeps
  # accepting it until `exp` (docs/ARCHITECTURE.md §3).
  #
  # Machine-token issuance and every revocation are recorded in the audit log
  # (TASK-029) in the same transaction; tokens appear there by `jti` only.
  # Issuance through the code and refresh grants is recorded by
  # OAuth::TokenRules.
  module Tokens
    Token = Struct.new(:jti, :client_uid, :client_name, :subject_id, :scopes, :resource, :created_at, :expires_at,
                       :refresh_expires_at, :revoked_at, keyword_init: true)

    module_function

    # Live tokens issued to a user, newest first: not revoked, and either the
    # access token has not expired or it came with a refresh token still
    # within its absolute lifetime (a signed-in app, for the account page).
    #
    # @param user [User]
    # @return [Array<Token>]
    def active_for(user:)
      Doorkeeper::AccessToken
        .where(resource_owner_id: user.id, revoked_at: nil)
        .order(created_at: :desc)
        .includes(:application)
        .map { |token| wrap(token) }
        .select { |token| live?(token) }
    end

    # Every machine token (client_credentials, RFC 6749 §4.4) is issued here:
    # Doorkeeper creates it in the block (OAuth::MachineGrantRules), so this is
    # the one hook for machine-token issuance and its audit event. The
    # client's `last_used_at` is touched as for the other grants
    # (OAuth::TokenRules). A client's earlier tokens are neither reused nor
    # revoked — Doorkeeper's revoke_previous_client_credentials_token stays
    # off — because a busy service may hold two while it rolls over.
    #
    # @param application [Doorkeeper::Application] the authenticated client
    # @yieldreturn [Doorkeeper::AccessToken, nil] the token Doorkeeper created
    # @return [Doorkeeper::AccessToken, nil]
    def issue_client_token(application:)
      Doorkeeper::AccessToken.transaction do
        token = yield
        if token
          # Registry metadata only; validations and updated_at are deliberately untouched.
          application.update_column(:last_used_at, Time.current) # rubocop:disable Rails/SkipsModelValidations
          Audit.record("token.issued", actor: nil, client_uid: application.uid, jti: token.jti,
                                       grant_type: "client_credentials", scopes: token.scopes.to_a)
        end
        token
      end
    end

    # Revokes one token and its family. The token is found by its `jti`, its
    # JWT or its refresh token. Only its owner or an administrator may revoke
    # it (clients revoke through POST /oauth/revoke, where Doorkeeper checks
    # that the token is theirs).
    #
    # @param token [String] a `jti`, an access token (JWT) or a refresh token
    # @param by [User] who asks
    # @return [Integer] number of access tokens revoked (0: unknown, not theirs, or already revoked)
    def revoke(token, by:)
      record = find_record(token)
      return 0 unless record && (by.is_admin || record.resource_owner_id == by.id)

      revoke_family!(record, actor: by)
    end

    # Revokes a token together with every live token issued from the same
    # authorization code: a refresh token takes its access tokens with it
    # (RFC 7009 §2.1). A token without a family (client_credentials) is
    # revoked alone.
    #
    # @param record [Doorkeeper::AccessToken]
    # @param actor [User, nil] who asks; none when the client revokes through POST /oauth/revoke
    # @return [Integer] number of access tokens revoked
    def revoke_family!(record, actor: nil)
      family = Doorkeeper::AccessToken.where(id: record.id)
      if record.access_grant_id
        family = family.or(Doorkeeper::AccessToken.where(access_grant_id: record.access_grant_id))
      end
      revoke_recorded("token.revoked", Doorkeeper::AccessGrant.none, family,
                      actor: actor, subject_id: record.resource_owner_id, client_uid: record.application&.uid,
                      jti: record.jti)
    end

    # Sign out everywhere: every live access token, refresh token and pending
    # authorization code of a user, all clients. Called when the password
    # changes and when an administrator disables the account (User); signing
    # out of the hub itself revokes nothing.
    #
    # @param user [User]
    # @param actor [User, nil] who asks; the signed-in user by default
    # @return [Integer] number of access tokens revoked
    def revoke_all_for(user:, actor: Current.user)
      revoke_recorded("tokens.revoked_for_user", Doorkeeper::AccessGrant.where(resource_owner_id: user.id),
                      Doorkeeper::AccessToken.where(resource_owner_id: user.id),
                      actor: actor, subject_id: user.id)
    end

    # Whether the access token with this `jti` is still live: a row exists and
    # was not revoked. One indexed query — the check a resource server needs
    # after verifying a self-contained JWT (the hub's own API does it in
    # Api::BaseController). Expiry is the token's own `exp`, already checked by
    # whoever verified the signature, so it is not re-derived here.
    #
    # @param jti [String, nil] the `jti` claim
    # @return [Boolean]
    def active?(jti:)
      return false if jti.blank?

      Doorkeeper::AccessToken.exists?(jti: jti, revoked_at: nil)
    end

    # Revokes every live access token, refresh token and authorization code of
    # a client (client revocation, TASK-016).
    #
    # @param client_uid [String]
    # @param actor [User, nil] who asks; the signed-in user by default
    # @return [Integer] number of access tokens revoked
    def revoke_all(client_uid:, actor: Current.user)
      app = Doorkeeper::Application.find_by(uid: client_uid)
      return 0 unless app

      revoke_recorded("tokens.revoked_for_client", app.access_grants, app.access_tokens,
                      actor: actor, client_uid: app.uid)
    end

    # Revokes the live tokens and codes one client holds for one user (consent
    # revocation, TASK-018; the account page reuses it in TASK-022).
    #
    # @param user [User]
    # @param client_uid [String]
    # @param actor [User, nil] who asks; the signed-in user by default
    # @return [Integer] number of access tokens revoked
    def revoke_for(user:, client_uid:, actor: Current.user)
      app = Doorkeeper::Application.find_by(uid: client_uid)
      return 0 unless app

      revoke_recorded("tokens.revoked_for_user_and_client", app.access_grants.where(resource_owner_id: user.id),
                      app.access_tokens.where(resource_owner_id: user.id),
                      actor: actor, subject_id: user.id, client_uid: app.uid)
    end

    # Absolute lifetime of a refresh token, counted from the authorization
    # code it descends from (rotation does not extend it). OAUTH_REFRESH_TOKEN_TTL
    # in seconds, 30 days by default (config/initializers/doorkeeper.rb).
    #
    # @return [ActiveSupport::Duration]
    def refresh_token_ttl
      Rails.configuration.x.oauth.refresh_token_ttl
    end

    # Whether a refresh token is still within its absolute lifetime.
    #
    # @param token [Doorkeeper::AccessToken] the token record carrying the refresh token
    # @return [Boolean]
    def refresh_token_alive?(token)
      refresh_token_expires_at(token) > Time.current
    end

    # Refresh-token reuse (RFC 6819 §5.2.2.3, OAuth 2.1 §4.3.1): a refresh
    # token that was already rotated is presented again, so a second party
    # holds a copy. The whole family the client holds for that user — live
    # tokens and pending codes — is revoked; the caller answers invalid_grant.
    #
    # @param token [Doorkeeper::AccessToken, nil] the record found for the presented refresh token
    # @return [Boolean] true when reuse was detected (and the family revoked)
    def detect_reuse!(token) # rubocop:disable Naming/PredicateMethod -- the bang marks the revocation side effect
      return false unless token&.revoked?

      app = token.application
      owner_id = token.resource_owner_id
      revoke_recorded("token.refresh_reuse_detected", app.access_grants.where(resource_owner_id: owner_id),
                      app.access_tokens.where(resource_owner_id: owner_id),
                      actor: nil, subject_id: owner_id, client_uid: app.uid, jti: token.jti)
      true
    end

    # Authorization-code replay (RFC 6749 §4.1.2, OAuth 2.1 §4.1.3): the code
    # was redeemed before, so every token issued from it (refresh rotations
    # included) is revoked; the caller answers invalid_grant.
    #
    # @param grant [Doorkeeper::AccessGrant]
    # @return [Integer] number of access tokens revoked
    def revoke_issued_from!(grant)
      revoke_recorded("token.code_replay_detected", Doorkeeper::AccessGrant.none,
                      Doorkeeper::AccessToken.where(access_grant_id: grant.id),
                      actor: nil, subject_id: grant.resource_owner_id, client_uid: grant.application&.uid)
    end

    # Revokes and records the revocation, together or not at all.
    def revoke_recorded(event, grants, tokens, actor:, **)
      Doorkeeper::AccessToken.transaction do
        revoked = revoke_live(grants, tokens)
        Audit.record(event, actor: actor, revoked: revoked, **)
        revoked
      end
    end
    private_class_method :revoke_recorded

    def revoke_live(grants, tokens)
      grants.where(revoked_at: nil).find_each(&:revoke)
      revoked = 0
      tokens.where(revoked_at: nil).find_each do |token|
        token.revoke
        revoked += 1
      end
      revoked
    end
    private_class_method :revoke_live

    # A `jti` first (the account page and admin tools hold only that), then
    # the token strings; the stored values are hashes, Doorkeeper's lookups
    # hash the candidate.
    def find_record(value)
      value = value.to_s
      return if value.blank?

      Doorkeeper::AccessToken.find_by(jti: value) ||
        Doorkeeper::AccessToken.by_token(value) ||
        Doorkeeper::AccessToken.by_refresh_token(value)
    end
    private_class_method :find_record

    def refresh_token_expires_at(token)
      origin = token.access_grant_id && Doorkeeper::AccessGrant.where(id: token.access_grant_id).pick(:created_at)
      (origin || token.created_at) + refresh_token_ttl
    end
    private_class_method :refresh_token_expires_at

    def live?(token)
      now = Time.current
      return true if token.expires_at.nil? || token.expires_at > now

      token.refresh_expires_at.present? && token.refresh_expires_at > now
    end
    private_class_method :live?

    def wrap(token)
      Token.new(
        jti: token.jti,
        client_uid: token.application&.uid,
        client_name: token.application&.name,
        subject_id: token.resource_owner_id,
        scopes: token.scopes.to_a,
        resource: token.resource,
        created_at: token.created_at,
        expires_at: token.expires_in && (token.created_at + token.expires_in.seconds),
        refresh_expires_at: token.refresh_token.present? ? refresh_token_expires_at(token) : nil,
        revoked_at: token.revoked_at
      )
    end
    private_class_method :wrap
  end
end
