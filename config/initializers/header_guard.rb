# Security headers via the header_guard gem: HSTS, X-Content-Type-Options,
# X-Frame-Options DENY, Referrer-Policy, Cross-Origin-Opener-Policy
# (same-origin-allow-popups: the hub is used through redirects, not as a
# popup), Cross-Origin-Resource-Policy, X-Permitted-Cross-Domain-Policies and
# Permissions-Policy — all gem defaults.
#
# The Content-Security-Policy header is deliberately NOT managed here:
# header_guard 0.3.1 only takes a static policy string, and the importmap and
# Turbo script tags need a per-request nonce, which Rails' own CSP middleware
# provides (see config/initializers/content_security_policy.rb). Nonce support
# in header_guard is a gem follow-up (TODO T46); until then the two middlewares
# split the work and never write the same header.
#
# HSTS is left on in every environment: browsers ignore it over plain HTTP, so
# it is harmless in development and lets the test suite assert the production
# header set.
Rails.application.config.middleware.use(
  HeaderGuard::Middleware,
  content_security_policy: false
)
