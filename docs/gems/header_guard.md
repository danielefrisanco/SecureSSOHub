# header_guard — handover prompt (0.3.1 → 0.4.0)

Paste this whole file into a Claude session opened in the `headerguard`
repository (`../headerguard`, last commit `4513be8`, version 0.3.1).
Priority: low. The hub works without this change; the value is consolidating
every security header in one middleware.

---

## Who is asking and why

I maintain `header_guard`, a Rack middleware that sets HSTS,
`X-Content-Type-Options`, `X-Frame-Options`, `Referrer-Policy`, COOP, CORP,
`X-Permitted-Cross-Domain-Policies`, `Permissions-Policy` and a strict default
Content-Security-Policy, with `report_only`, `html_only`, `path_overrides` and
boot-time option validation. I also build **SecureSSOHub** (`../SecureSSOHub`),
a Rails 8.1 OAuth 2.1 / OpenID Connect server that mounts the gem for every
header **except** the CSP. This is TODO T46 on the hub side.

## How the hub uses the gem today, and why the CSP is not in it

`config/initializers/header_guard.rb` (hub):

```ruby
Rails.application.config.middleware.use(HeaderGuard::Middleware, content_security_policy: false)
```

`config/initializers/content_security_policy.rb` (hub) builds the CSP with the
Rails DSL instead, for two reasons the gem cannot meet with a static policy
string:

1. **Per-request nonces.** The hub uses importmap and Turbo:
   `javascript_importmap_tags` emits an inline `<script type="importmap">` and
   an inline module script, so an enforced `script-src` needs a per-request
   `'nonce-…'`. Rails generates the nonce
   (`config.content_security_policy_nonce_generator`), stamps it on those
   tags, and publishes it through `csp_meta_tag` in the layout, which Turbo
   reads. A static string would force `'unsafe-inline'`.
2. **Per-request directive values.** The OAuth consent page
   (`app/services/oauth/consent_screen.rb`) widens two directives for one
   controller only: `img-src` adds `https:` (the client's logo) and
   `form-action` adds the **validated redirect target of that request**
   (browsers check `form-action` against the redirect that follows the
   Allow/Deny POST, so `'self'` alone blocks the flow in Chrome). The value
   depends on the request's `redirect_uri`, so it cannot be a `path_overrides`
   entry.

Everything else in the gem is used as shipped (all header defaults), and the
hub's suite asserts the production header set.

## Requested changes

### 1. Per-request policy (callable) — needed for point 2

Let `content_security_policy:` (top level and inside `path_overrides`) accept
a callable in addition to a String or `false`:

```ruby
use HeaderGuard::Middleware,
    content_security_policy: ->(env) { "default-src 'self'; form-action 'self' #{env["myapp.csp_form_action"]}" }
```

Called once per request **after** the app responded (so the app can leave
hints in `env`), with the Rack env; returns a String, or `nil`/`false` to
send no CSP for that response. Validate at boot only that it responds to
`#call`; validate the returned value per request the same way strings are
validated today (raise nothing at request time: log and skip the header if
the callable raises, so a bug never takes the site down — document this).

Also accept a per-request override from the application: if the app sets
`env["header_guard.content_security_policy"]` (String or `false`) the
middleware uses it for that response. That is the simplest bridge for a
Rails controller that needs to widen one directive.

### 2. Nonce support — needed for point 1

Add `csp_nonce:` (default `false`):

- `true`: generate a 128-bit random nonce per request (base64), expose it as
  `env["header_guard.csp_nonce"]` **before** calling the app, and substitute
  the placeholder `{nonce}` (or a clearer token you prefer, e.g.
  `HeaderGuard::NONCE`) in the policy string with `'nonce-<value>'` when
  writing the header. Only substitute; never add `'nonce-…'` to a directive
  that does not mention the placeholder.
- a callable `->(env) { String }`: use the application's nonce instead of
  generating one. This is the Rails bridge: Rails exposes its nonce as
  `request.content_security_policy_nonce`, which is stored in
  `env["action_dispatch.content_security_policy_nonce"]` once generated. **Verify
  in the installed actionpack** how the nonce is generated and stored when the
  Rails CSP DSL is *not* configured (the middleware `ActionDispatch::ContentSecurityPolicy::Middleware`
  is always in the stack; check whether `content_security_policy_nonce_generator`
  alone is enough for `csp_meta_tag` and `javascript_importmap_tags` to stamp
  the nonce while header_guard writes the header). Document the exact Rails
  setup that results: which Rails config keys stay, which move to header_guard.
- Provide `HeaderGuard.csp_nonce(env)` as the accessor applications use in
  views (for a plain Rack/Sinatra app).

The hub-side goal after this change: delete the Rails CSP initializer, move
the policy into `HeaderGuard::Middleware` with `csp_nonce:` bridged to Rails'
nonce, and keep the consent-page override through the env hook.

### 3. Keep the existing guarantees

- `content_security_policy: nil` must still mean "default policy", `false`
  "no CSP" (the README makes a point of that; keep the spec).
- `report_only`, `html_only`, `path_overrides` layering unchanged; a callable
  or env override participates in the same layering (path override wins over
  global; env override wins over both).
- Option validation at boot for everything that can be validated at boot.

## Tests to add (`spec/header_guard/middleware_spec.rb`)

- Callable policy: receives the env, its String is sent; `nil`/`false` sends
  no CSP; a raising callable logs (to `env["rack.logger"]` or a `logger:`
  option) and sends no CSP; `report_only` applies to the callable's value.
- Env override `header_guard.content_security_policy` wins over global and
  path policies; `false` suppresses the header for that response.
- `csp_nonce: true`: nonce in env before the app runs, `{nonce}` replaced in
  the header, different per request, not substituted when the placeholder is
  absent, `HeaderGuard.csp_nonce(env)` returns it.
- `csp_nonce:` callable: the header uses the app-provided value.
- A Rails smoke spec (development dependency `rails`/`actionpack` only in the
  test group, or a separate `spec/rails` folder run in CI): a minimal Rails
  app with importmap-style inline script rendered with the bridged nonce
  produces a page whose script nonce matches the header nonce.

## Docs, versioning, release

- Version 0.4.0. CHANGELOG. README: "Per-request policies", "Nonces"
  (including the Rails bridge and the importmap/Turbo case), and update the
  "Rails CSP DSL" paragraph that today tells users to pass `false`.
- Rubocop clean, suite green, `gem build` clean.

## Verifying against the hub

```ruby
# ../SecureSSOHub/Gemfile (temporarily)
gem "header_guard", path: "../headerguard"
```

Run `POSTGRES_HOST=localhost bundle exec rspec spec/requests` in the hub with
the current initializers (must stay green: `content_security_policy: false`
is untouched). Then, locally only, try the intended hub-side setup: policy in
header_guard with the bridged nonce, Rails CSP initializer removed, and check
`spec/requests/oauth/consent_spec.rb` (asserts nonced scripts, no inline
styles, `form-action` including the redirect target) and the landing/Devise
page specs. That local edit becomes the hub's T46 task after the release.

## Definition of done

- Changes 1–3 implemented, spec'd, documented, released as 0.4.0.
- A note back to the hub: exact option names, the Rails bridge recipe that
  worked, and anything in Rails' nonce handling you had to work around.
