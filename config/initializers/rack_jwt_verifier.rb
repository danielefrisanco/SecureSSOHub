require "openssl"
require "rack_jwt_verifier"

# Bearer-token guard for the hub's own API (`/api/**`): rack-jwt-verifier, the
# same gem every downstream service uses, verifying the hub's own access
# tokens. Everything else — Devise pages, /oauth/*, /.well-known/* — is skipped.
#
# Key material stays in-process. The gem's key sources are a single
# `public_key` or a `jwks_url` fetched over HTTP; neither fits a hub that has
# two published keys during a rotation and must never fetch from itself. So
# the active public key satisfies the gem's "one key source" rule, and the
# verification set that is actually used is the hub's JWKS handed to ruby-jwt
# as the `jwks` decode option (a callable resolved per request, so a key
# rotation needs no restart; ruby-jwt prefers `jwks` over the positional key
# and selects by `kid`). The gem should grow an in-process key-set source:
# TODO.md T48 `[gem: rack-jwt-verifier]`.
#
# Claims: `iss` must be this hub and `aud` the hub API resource
# (OAuth::Resources.hub_api) — a token minted for a client's own audience or
# for the MCP endpoint is refused as invalid_token. RS256 only; 30 seconds of
# clock skew; a request without a token is refused here (require_token) with
# the RFC 6750 challenge; errors are JSON like every other API response.
# replay_cache stays off until Redis is the shared cache (TODO.md T23):
# revocation is checked per request against the database instead
# (Api::BaseController), which the 10-minute lifetime keeps sufficient.
#
# The key is read from config.x (set by doorkeeper.rb, which runs first)
# because initializers cannot use autoloaded code; OAuth::SigningKey is only
# touched at request time, inside the callable. Under SECRET_KEY_BASE_DUMMY
# (asset precompile) there is no key: a throwaway one keeps the guard mounted,
# so `/api/**` is never served unguarded, and nothing can verify against it.
active_pem = Rails.application.config.x.oauth.signing_key_pems.first
active_public_key = OpenSSL::PKey::RSA.new(active_pem || 2048).public_key
issuer = Rails.application.config.x.oauth.issuer

# The predicate sees the path exactly as the router will: Journey squeezes
# repeated slashes and drops a trailing one before matching routes, so
# "//api/v1/userinfo" is served by the API and must be guarded too.
outside_api = lambda do |env|
  path = ActionDispatch::Journey::Router::Utils.normalize_path("#{env['SCRIPT_NAME']}#{env['PATH_INFO']}")
  !path.match?(%r{\A/api(/|\z)})
end

# Mounted outside Warden: the API is bearer-only and its 401s must never be
# rewritten as a sign-in redirect. Devise only switches Warden's 401
# interception off when the routes are finalised, which happens lazily in
# development and test — a first request refused here before the router
# ever ran would otherwise crash inside Warden ("No Failure App provided").
Rails.application.config.middleware.insert_before(
  Warden::Manager,
  RackJwtVerifier::Middleware,
  skip: [outside_api],
  public_key: active_public_key,
  algorithms: %w[RS256],
  decode_options: {
    iss: issuer,
    aud: "#{issuer}/api", # OAuth::Resources.hub_api, which cannot be autoloaded here
    leeway: 30,
    jwks: ->(_options) { OAuth::SigningKey.for(realm: :default).jwks }
  },
  require_token: true,
  json_errors: true
)
