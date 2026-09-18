module OAuth
  # The consent page, prepended into Doorkeeper::AuthorizationsController from
  # config/initializers/doorkeeper.rb. Doorkeeper decides *whether* to ask
  # (skip_authorization → OAuth::Consents.covers?); this module makes the page
  # the hub's own and records the answer:
  #
  #   - the view (app/views/doorkeeper/authorizations/new.html.erb) renders in
  #     the application layout, under the app's CSP. Two directives are
  #     widened for this controller only: img-src admits any https origin for
  #     the client's logo, and form-action admits the client's redirect target
  #     because browsers check it against the redirect that follows Allow/Deny;
  #   - `consent` hands the view the hub-level client (OAuth::Clients::Client),
  #     the requested scopes with their catalogue descriptions — marking the
  #     ones not yet consented so a scope escalation stands out — and the
  #     request parameters the Allow/Deny forms must carry (Doorkeeper's own
  #     view drops the RFC 8707 `resource` and the OIDC `nonce`);
  #   - after every successful authorization (Allow, or a skipped page) the
  #     scopes are merged into the user's standing consent for the client.
  module ConsentScreen
    # One line of the consent page.
    Permission = Struct.new(:scope, :description, :new, keyword_init: true) do
      alias_method :new?, :new
    end

    # What the page shows and submits.
    Consent = Struct.new(:client, :permissions, :request_params, keyword_init: true) do
      # @return [String, nil] the client's logo, https only
      def logo_uri
        uri = client.logo_uri.presence
        uri if uri && URI.parse(uri).is_a?(URI::HTTPS)
      rescue URI::InvalidURIError
        nil
      end

      # Some of the requested scopes were consented before, some are new.
      def escalation?
        permissions.any?(&:new?) && !permissions.all?(&:new?)
      end

      # CSP source expression matching the (already validated) redirect_uri:
      # an origin, or the bare scheme of a private-use URI.
      #
      # @return [String]
      def redirect_source
        uri = URI.parse(request_params.fetch(:redirect_uri))
        return "#{uri.scheme}:" unless uri.host

        port = uri.port == uri.default_port ? "" : ":#{uri.port}"
        "#{uri.scheme}://#{uri.host}#{port}"
      end
    end

    def self.prepended(base)
      base.layout "application"
      base.helper_method :consent
      base.content_security_policy do |policy|
        policy.img_src :self, :data, :https
        policy.form_action :self, -> { @consent ? [@consent.redirect_source] : [] }
      end
    end

    private

    def consent
      @consent ||= begin
        client = OAuth::Clients.find(pre_auth.client.uid)
        granted = OAuth::Consents.granted_scopes(user: current_resource_owner, client_uid: client.uid)
        permissions = pre_auth.scopes.to_a.map do |scope|
          Permission.new(scope: scope, description: OAuth::Scopes.description(scope) || scope,
                         new: granted.exclude?(scope))
        end
        Consent.new(client: client, permissions: permissions, request_params: consent_request_params)
      end
    end

    # The normalised request (default scopes and response_mode applied), blank
    # values dropped: an empty `resource` would be an invalid_target.
    def consent_request_params
      {
        client_id: pre_auth.client.uid, redirect_uri: pre_auth.redirect_uri, state: pre_auth.state,
        response_type: pre_auth.response_type, response_mode: pre_auth.response_mode, scope: pre_auth.scope,
        code_challenge: pre_auth.code_challenge, code_challenge_method: pre_auth.code_challenge_method,
        resource: pre_auth.resource, nonce: pre_auth.nonce
      }.compact_blank
    end

    def after_successful_authorization(context)
      super
      OAuth::Consents.grant(user: current_resource_owner, client_uid: pre_auth.client.uid,
                            scopes: pre_auth.scopes.to_a)
    end
  end
end
