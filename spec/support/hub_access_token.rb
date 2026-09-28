require "base64"
require "digest"

# Obtains a real access token from the in-process hub the way a client does:
# authorization code with S256 PKCE, then the token endpoint. For request
# specs (needs `sign_in`, `post`, `response`).
module HubAccessToken
  CODE_VERIFIER = "b" * 43
  CODE_CHALLENGE = Base64.urlsafe_encode64(Digest::SHA256.digest(CODE_VERIFIER), padding: false)

  # @param user [User] the resource owner (signed in and out around the request)
  # @param client [Doorkeeper::Application] a public client registered with `redirect_uri` and the scopes
  # @param scope [String] space-delimited scopes to request
  # @param resource [String, nil] RFC 8707 resource indicator (the token's `aud`)
  # @return [Hash] the token response body (access_token, token_type, id_token, ...)
  def obtain_token_response(user:, client:, scope:, resource: nil)
    sign_in user
    post "/oauth/authorize", params: { client_id: client.uid, redirect_uri: client.redirect_uri, response_type: "code",
                                       scope: scope, code_challenge: CODE_CHALLENGE, code_challenge_method: "S256",
                                       resource: resource }.compact
    sign_out user
    code = Rack::Utils.parse_query(URI.parse(response.location).query).fetch("code")

    post "/oauth/token", params: { grant_type: "authorization_code", client_id: client.uid, code: code,
                                   redirect_uri: client.redirect_uri, code_verifier: CODE_VERIFIER }
    response.parsed_body
  end

  # @return [String] the access token alone
  def obtain_access_token(**)
    obtain_token_response(**).fetch("access_token")
  end
end
