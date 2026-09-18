module OAuth
  # Issued access/refresh tokens as the application sees them. Per-token
  # revocation and "sign out everywhere" arrive with TASK-022; the token
  # payload with TASK-019.
  module Tokens
    Token = Struct.new(:jti, :client_uid, :subject_id, :scopes, :resource, :created_at, :expires_at, :revoked_at,
                       keyword_init: true)

    module_function

    # Active (not revoked, not expired) tokens issued to a user, newest first.
    #
    # @param user [User]
    # @return [Array<Token>]
    def active_for(user:)
      Doorkeeper::AccessToken
        .where(resource_owner_id: user.id, revoked_at: nil)
        .order(created_at: :desc)
        .includes(:application)
        .map { |token| wrap(token) }
        .reject { |token| token.expires_at && token.expires_at <= Time.current }
    end

    # Revokes every live access token, refresh token and authorization code of
    # a client (client revocation, TASK-016).
    #
    # @param client_uid [String]
    # @return [Integer] number of access tokens revoked
    def revoke_all(client_uid:)
      app = Doorkeeper::Application.find_by(uid: client_uid)
      return 0 unless app

      revoke_live(app.access_grants, app.access_tokens)
    end

    # Revokes the live tokens and codes one client holds for one user (consent
    # revocation, TASK-018; the account page reuses it in TASK-022).
    #
    # @param user [User]
    # @param client_uid [String]
    # @return [Integer] number of access tokens revoked
    def revoke_for(user:, client_uid:)
      app = Doorkeeper::Application.find_by(uid: client_uid)
      return 0 unless app

      revoke_live(app.access_grants.where(resource_owner_id: user.id),
                  app.access_tokens.where(resource_owner_id: user.id))
    end

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

    def wrap(token)
      Token.new(
        jti: token.token,
        client_uid: token.application&.uid,
        subject_id: token.resource_owner_id,
        scopes: token.scopes.to_a,
        resource: token.resource,
        created_at: token.created_at,
        expires_at: token.expires_in && (token.created_at + token.expires_in.seconds),
        revoked_at: token.revoked_at
      )
    end
    private_class_method :wrap
  end
end
