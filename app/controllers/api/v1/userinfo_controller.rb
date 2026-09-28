module Api
  module V1
    # GET /api/v1/userinfo — the profile document omniauth-ssoprovider 0.1.2
    # hard-codes: `id` is the uid, `name` and `email` feed the info hash. The
    # OIDC equivalent is /oauth/userinfo (doorkeeper-openid_connect).
    #
    #   id, sub      the user's sso_id (always)
    #   name         with the `profile` scope
    #   email,
    #   email_verified  with the `email` scope
    #   roles        ["admin"] for an administrator, else [] (always)
    #
    # The same scope gating as the access token and the id_token
    # (docs/ARCHITECTURE.md §3): nothing else about the user is exposed.
    class UserinfoController < BaseController
      before_action :require_user

      def show
        render json: userinfo
      end

      private

      def userinfo
        document = { id: current_user.sso_id, sub: current_user.sso_id }
        document[:name] = current_user.name if token_scopes.include?("profile")
        if token_scopes.include?("email")
          document[:email] = current_user.email
          document[:email_verified] = current_user.confirmed_at.present?
        end
        document.merge(roles: current_user.is_admin ? ["admin"] : [])
      end
    end
  end
end
