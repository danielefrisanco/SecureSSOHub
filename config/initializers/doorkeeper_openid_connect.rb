# OpenID Connect layer on top of Doorkeeper (id_token, userinfo, discovery).
# The signing key is shared with doorkeeper-jwt through config.x.oauth
# (set in doorkeeper.rb, replaced by SigningKey in TASK-015).
Doorkeeper::OpenidConnect.configure do
  # Canonical https URL of this hub; every issued token carries it as `iss`
  # and discovery documents are built from it — never from the request Host.
  issuer do |_resource_owner, _application, _request|
    ENV.fetch("HUB_ISSUER") { Rails.env.local? ? "http://localhost:3000" : raise("HUB_ISSUER is not set") }
  end

  signing_key Rails.application.config.x.oauth.signing_key_pem
  signing_algorithm :rs256

  subject_types_supported [:public]

  resource_owner_from_access_token do |access_token|
    User.find_by(id: access_token.resource_owner_id)
  end

  auth_time_from_resource_owner(&:current_sign_in_at)

  # `prompt=login` or an expired max_age: sign the user out and back to sign-in,
  # returning to the authorization request afterwards.
  reauthenticate_resource_owner do |resource_owner, return_to|
    store_location_for resource_owner, return_to
    sign_out resource_owner
    redirect_to new_user_session_url
  end

  # The stable identifier across every trusting service (never the email).
  subject do |resource_owner, _application|
    resource_owner.sso_id
  end

  # Scope-gated claims (name/email) are added in TASK-019.
end
