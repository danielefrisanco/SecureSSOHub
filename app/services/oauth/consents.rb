module OAuth
  # A user's standing consents (OAuthConsent rows) as the authorization
  # endpoint and the account page see them. One live consent per user and
  # client; its scopes only ever grow (`grant` merges) until `revoke` closes
  # it, after which the client has to ask again.
  #
  # Doorkeeper's `skip_authorization` consults `covers?` so a repeat
  # authorization for the same client and a subset of the consented scopes
  # skips the consent page (config/initializers/doorkeeper.rb).
  module Consents
    Consent = Struct.new(:client_uid, :subject_id, :scopes, :granted_at, :revoked_at, keyword_init: true)

    module_function

    # @param user [User]
    # @param client_uid [String]
    # @param scopes [Enumerable<String>] the scopes the client is asking for
    # @return [Boolean] whether a live consent already covers every scope
    def covers?(user:, client_uid:, scopes:)
      (Array(scopes).map(&:to_s) - granted_scopes(user: user, client_uid: client_uid)).empty?
    end

    # Scopes the user currently allows the client (empty when none or revoked).
    #
    # @return [Array<String>]
    def granted_scopes(user:, client_uid:)
      live_record(user, client_uid)&.scope_list || []
    end

    # Records (or widens) the user's consent for the client.
    #
    # @param user [User]
    # @param client_uid [String]
    # @param scopes [Enumerable<String>]
    # @return [Consent]
    def grant(user:, client_uid:, scopes:)
      app = fetch_application(client_uid)
      record = OAuthConsent.live.find_or_initialize_by(user: user, oauth_application_id: app.id)
      record.scope_list = record.scope_list | Array(scopes).map(&:to_s)
      record.granted_at = Time.current
      record.save!
      wrap(record, app.uid)
    end

    # Closes the live consent and revokes the tokens and codes the client
    # holds for the user, so the client is back to square one.
    #
    # @return [Consent, nil] the closed consent, nil when there was none
    def revoke(user:, client_uid:)
      record = live_record(user, client_uid)
      return nil unless record

      record.update!(revoked_at: Time.current)
      OAuth::Tokens.revoke_for(user: user, client_uid: client_uid)
      wrap(record, client_uid)
    end

    # Live consents of a user, newest first (the account page, Phase 3).
    #
    # @return [Array<Consent>]
    def for(user:)
      records = OAuthConsent.live.where(user: user).order(granted_at: :desc).to_a
      uids = Doorkeeper::Application.where(id: records.map(&:oauth_application_id)).pluck(:id, :uid).to_h
      records.map { |record| wrap(record, uids.fetch(record.oauth_application_id)) }
    end

    def live_record(user, client_uid)
      app_id = Doorkeeper::Application.where(uid: client_uid).pick(:id)
      app_id && OAuthConsent.live.find_by(user: user, oauth_application_id: app_id)
    end
    private_class_method :live_record

    def fetch_application(client_uid)
      Doorkeeper::Application.find_by(uid: client_uid) ||
        raise(OAuth::Clients::NotFound, "no client with client_id #{client_uid}")
    end
    private_class_method :fetch_application

    def wrap(record, client_uid)
      Consent.new(client_uid: client_uid, subject_id: record.user_id, scopes: record.scope_list,
                  granted_at: record.granted_at, revoked_at: record.revoked_at)
    end
    private_class_method :wrap
  end
end
