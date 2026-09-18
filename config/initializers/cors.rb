# Cross-origin access to the public discovery documents and the JWKS only:
# browser-based clients (SPAs, MCP inspectors) fetch them from another
# origin. Read-only GET, no cookies. The token, userinfo and MCP endpoints
# stay same-origin until the full policy (TODO T28) lands.
Rails.application.config.middleware.insert_before 0, Rack::Cors do
  allow do
    origins "*"
    resource "/.well-known/*", headers: :any, methods: %i[get options], max_age: 300
    resource "/oauth/discovery/keys", headers: :any, methods: %i[get options], max_age: 300
  end
end
