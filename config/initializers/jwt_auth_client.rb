# Token signing configuration for JwtAuthClient (User#to_jwt, TokenIssuer).
#
# The signing key comes only from the environment: there is deliberately no
# fallback value, so a missing or too-short JWT_SERVICE_SECRET (>= 32 bytes,
# e.g. `openssl rand -hex 32`) fails the boot instead of signing with a known
# key. The one exception is the asset-precompile step of the Docker build,
# which Rails runs with SECRET_KEY_BASE_DUMMY set and no real configuration.
#
# HMAC is a stopgap: the hub will move to asymmetric keys + JWKS (TODO T11/T12).
unless ENV["SECRET_KEY_BASE_DUMMY"]
  JwtAuthClient.configure do |config|
    config.shared_secret = ENV.fetch("JWT_SERVICE_SECRET")
    config.issuer = ENV.fetch("JWT_ISSUER", "secure-sso-hub")
    config.algorithm = "HS256"
    config.default_expiry_seconds = 300
  end
end
