module OAuth
  # Authorization grants (codes) as the application sees them. Consent records
  # (TASK-018) and grant inspection for the account page build on this.
  module Grants
    Grant = Struct.new(:client_uid, :subject_id, :scopes, :redirect_uri, :resource, :code_challenge_method,
                       :created_at, :expires_at, :revoked_at, keyword_init: true)

    module_function

    # Grants issued to a user, newest first (revoked and expired included —
    # callers filter; the account page shows history).
    #
    # @param user [User]
    # @return [Array<Grant>]
    def for(user:)
      Doorkeeper::AccessGrant
        .where(resource_owner_id: user.id)
        .order(created_at: :desc)
        .includes(:application)
        .map { |grant| wrap(grant) }
    end

    def wrap(grant)
      Grant.new(
        client_uid: grant.application&.uid,
        subject_id: grant.resource_owner_id,
        scopes: grant.scopes.to_a,
        redirect_uri: grant.redirect_uri,
        resource: grant.resource,
        code_challenge_method: grant.code_challenge_method,
        created_at: grant.created_at,
        expires_at: grant.created_at + grant.expires_in.seconds,
        revoked_at: grant.revoked_at
      )
    end
    private_class_method :wrap
  end
end
