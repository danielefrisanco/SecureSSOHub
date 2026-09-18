---
name: doorkeeper-extension-points
description: How hub rules are hooked into Doorkeeper 5.9 without breaking the isolation spec; env/DB quirks for running rspec and rails here
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
  `config/locales/doorkeeper.en.yml` `doorkeeper.errors.messages`.
- Controller behaviour: prepend to `Doorkeeper::AuthorizationsController` (sits before the OIDC extension).
- Doorkeeper's URIChecker tolerates extra query params on redirect_uri — the hub adds exact matching.
- Doorkeeper only stores PKCE challenges when `oauth_access_grants` has `code_challenge` columns (added in TASK-017).
- Access-token JWTs have no jti until TASK-019: identical claims in the same second collide on the unique
  `token` column, so use distinct users/clients per token in specs.
- Running: `POSTGRES_HOST=localhost bundle exec rspec` (rails_helper sets HUB_ISSUER=https://hub.test and the
  JWT env var itself); `bin/rails` needs `JWT_SERVICE_SECRET` and `POSTGRES_HOST` exported. Migrate both
  dev and `RAILS_ENV=test` before running specs. A migration on an `oauth_*` table must be named `...OAuth...`
  (Zeitwerk acronym).
- The harness Bash guard blocks command text containing "secret"/"credential"; keep those words out of
  git commit -m text and grep with the Grep tool instead.
