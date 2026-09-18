---
name: doorkeeper-extension-points
description: How hub rules are hooked into Doorkeeper 5.9 without breaking the isolation spec; consent page/CSP quirks; env/DB quirks for running rspec and rails here
metadata:
  type: project
---

Hub rules are prepended into Doorkeeper classes from `config/initializers/doorkeeper.rb` (after_initialize)
with the modules living in `app/services/oauth/` (the only app dir allowed to name `Doorkeeper::`, enforced by
`spec/architecture/doorkeeper_isolation_spec.rb`). Specs are exempt from that rule.

**Why:** Doorkeeper stays swappable (docs/ARCHITECTURE.md §4); controllers/models must not name it.

**How to apply:**
- Validations on the authorize request: prepend a module to `Doorkeeper::OAuth::PreAuthorization`, override
  `validate_<attr>` (names fixed by Doorkeeper's `validate :attr` DSL — disable Naming/PredicateMethod inline)
  or register a new one in `self.prepended(base) { base.validate :x, error: SomeBaseResponseError }`.
  Error name = class name demodulized (`InvalidTarget` -> `invalid_target`), text from
  `config/locales/doorkeeper.en.yml` `doorkeeper.errors.messages`. `valid?` re-runs all validations on
  every call (not memoized).
- Controller behaviour: prepend to `Doorkeeper::AuthorizationsController` (sits before the OIDC extension).
  Class-level DSL (`layout`, `helper_method`, `content_security_policy`) goes in `self.prepended(base)`.
  `skip_authorization` block is instance_exec'd in the controller with `[resource_owner, client]`, so
  `pre_auth.scopes` is reachable there. `after_successful_authorization(context)` is the hook that runs only
  on a successful Allow/skip (not on Deny).
- Doorkeeper's own `authorizations/new` template drops `resource` (custom_access_token_attributes) and the
  OIDC `nonce`; the hub view carries them and omits blank values (an empty `resource` is invalid_target).
- Consent page CSP: `form-action 'self'` blocks the post-submit redirect to the client in Chrome, so the
  authorizations controller widens form-action to the validated redirect origin per request (Rails CSP
  accepts a lambda returning strings). Turbo cannot follow the cross-origin redirect: forms use
  `data: { turbo: false }`.
- Doorkeeper's URIChecker tolerates extra query params on redirect_uri — the hub adds exact matching.
- Doorkeeper only stores PKCE challenges when `oauth_access_grants` has `code_challenge` columns (added in TASK-017).
- Access-token JWTs have no jti until TASK-019: identical claims in the same second collide on the unique
  `token` column, so use distinct users/clients per token in specs, or `Timecop.travel(1.second.from_now)`.
- Running: `POSTGRES_HOST=localhost bundle exec rspec` (rails_helper sets HUB_ISSUER=https://hub.test and the
  JWT env var itself); `bin/rails` needs `JWT_SERVICE_SECRET` and `POSTGRES_HOST` exported. Migrate both
  dev and `RAILS_ENV=test` before running specs. A migration on an `oauth_*` table must be named `...OAuth...`
  (Zeitwerk acronym); model for `oauth_consents` is `OAuthConsent` in `app/models/oauth_consent.rb`.
- The harness Bash guard blocks command text containing "secret"/"credential" (even inside heredoc text
  or commit bodies) and any path under `tmp/` (gitignored); a chained command with `&&` around
  `git commit` may be rejected as a whole — run commits alone. `rubocop -a` will not fix Rails/Pluck; edit by hand.
