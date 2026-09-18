module OAuth
  # Issued access/refresh tokens as the application sees them. Revocation and
  # "sign out everywhere" arrive with TASK-022; the token payload with TASK-019.
  module Tokens
    Token = Struct.new(:jti, :client_uid, :subject_id, :scopes, :created_at, :expires_at, :revoked_at,
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
    # a client (client revocation, TASK-016). Per-user and per-token revocation
    # come with TASK-022.
    #
    # @param client_uid [String]
    # @return [Integer] number of access tokens revoked
    def revoke_all(client_uid:)
      app = Doorkeeper::Application.find_by(uid: client_uid)
      return 0 unless app

      app.access_grants.where(revoked_at: nil).find_each(&:revoke)
      revoked = 0
      app.access_tokens.where(revoked_at: nil).find_each do |token|
        token.revoke
        revoked += 1
      end
      revoked
    end

    def wrap(token)
      Token.new(
        jti: token.token,
        client_uid: token.application&.uid,
        subject_id: token.resource_owner_id,
        scopes: token.scopes.to_a,
        created_at: token.created_at,
        expires_at: token.expires_in && (token.created_at + token.expires_in.seconds),
        revoked_at: token.revoked_at
      )
    end
    private_class_method :wrap
  end
end
