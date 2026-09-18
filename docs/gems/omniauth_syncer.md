# omniauth_syncer — handover prompt (0.1.0 → 0.2.0)

Paste this whole file into a Claude session opened in the `omniauth_syncer`
repository (`../omniauth_syncer`, last commit `ec10706`, version 0.1.0).
Priority: low. This is TODO T45 on the hub side.

---

## Who is asking and why

I maintain `omniauth_syncer`: `SyncService.call(auth_hash)` finds or
initialises a local user by a configured uid field, copies mapped attributes
out of the OmniAuth auth hash (`info.email` → `email`, …) and `save!`s;
`ControllerHelpers#sync_sso_user` wraps it for an OmniAuth callback
controller. I also build **SecureSSOHub** (`../SecureSSOHub`), the SSO server,
and `omniauth-ssoprovider`, the client strategy. The hub does not use this
gem (the hub *owns* users, it does not sync them), so the gem's job is the
**client application** side: take the auth hash `omniauth-ssoprovider`
produces after a hub login and keep a local user row in step with it.

## The auth hash the gem will receive (omniauth-ssoprovider 0.2.0)

After the changes requested in `omniauth-ssoprovider.md`, a hub login yields:

```ruby
{
  "provider" => "ssoprovider",
  "uid"      => "<sso_id>",                       # stable, the hub's `sub`
  "info"     => { "name" => "…", "email" => "…" }, # each nil without its scope
  "extra"    => {
    "raw_info"       => { "id" => "<sso_id>", "sub" => "<sso_id>", "name" => "…",
                          "email" => "…", "email_verified" => false, "roles" => ["admin"] },
    "access_token"   => "<RS256 JWT, 10 min>",
    "refresh_token"  => "<opaque or nil>",
    "expires_at"     => 1758200000,
    "id_token"       => { "sub" => "…", "iss" => "…", "aud" => "…", "nonce" => "…", … },
    "roles"          => ["admin"],                # or []
    "email_verified" => false
  }
}
```

`uid` is the only stable identity; email can change on the hub. `roles`
carries `"admin"` only for hub administrators; it is the hub's *assertion*,
not an entitlement system (licensing/authorization live in a separate service
in this architecture).

## Findings against 0.1.0

1. `lib/omniauth_syncer/engine.rb` declares a `Rails::Engine` but
   `lib/omniauth_syncer.rb` never requires it, so the engine (and its
   commented-out controller mixin initializer) never loads; the engine's two
   initializers are empty placeholders.
2. `ControllerHelpers` is not required from the entry point either; a host
   app must `require "omniauth_syncer/controller_helpers"` by hand.
3. `SyncService#get_auth_value` (dotted path lookup into the auth hash) has no
   tests; `spec/omniauth_syncer/sync_service_spec.rb` is the only spec and
   there is no CI config.
4. `find_or_initialize_by(uid_field => uid)` with no `provider` in the lookup:
   two providers with overlapping uids collide. Also no handling for an
   existing user with the same email but a different uid (account linking is
   a policy question; today it raises on the unique index or silently creates
   a duplicate depending on the host schema).
5. Mapped values are copied only when `present?`, so a value that becomes
   blank on the SSO side (e.g. name removed) is never cleared; document or
   make it an option.
6. `user.send("#{local_attr}=")` with configuration-supplied attribute names
   is fine, but the configuration is never validated (unknown attribute →
   `NoMethodError` at login time rather than at boot).

## Requested changes

1. Entry point: `require "omniauth_syncer/controller_helpers"` from
   `lib/omniauth_syncer.rb`; require the engine only when Rails is loaded
   (`require "omniauth_syncer/engine" if defined?(::Rails::Engine)`), and give
   the engine a purpose: an initializer that includes `ControllerHelpers`
   into `ActionController::Base` on `:action_controller_base` load **only if**
   `OmniauthSyncer.configuration.include_controller_helpers` is true (default
   false). Or delete the engine; either is fine, but not a dead file.
2. Identity: look users up by `(provider, uid)` when the configured model has
   a `provider` column (configurable `provider_field`), by `uid` alone
   otherwise. Add an `on_conflict:` policy for "same email, different uid":
   `:raise` (default), `:link` (attach the uid to the existing row), `:ignore`.
3. Defaults tuned to the hub auth hash: `uid_field_in_auth: "uid"`, mappings
   `email: "info.email"`, `name: "info.name"`, plus opt-in mappings for
   `extra.roles` (e.g. `admin: ->(auth) { auth.dig("extra", "roles").include?("admin") }`,
   so a mapping value may be a callable as well as a dotted path) and
   `extra.email_verified`. Document that `extra.access_token` must not be
   persisted (10-minute token) and that `refresh_token`, if stored, must be
   encrypted.
4. `clear_blank: false|true` option (finding 5) with a spec each way.
5. Configuration validation at boot (`validate!`): model constantises,
   uid field exists, every mapped attribute has a writer, `on_conflict` is a
   known value; `ConfigurationError` with a precise message.
6. Spec suite: `SyncService` (create, update, blank handling, callable
   mappings, provider+uid lookup, conflict policies), `get_auth_value`
   (nested, missing, symbol vs string keys, `OmniAuth::AuthHash`),
   `ControllerHelpers` with a minimal controller double, configuration
   validation. Use an in-memory SQLite ActiveRecord model in the spec
   (development dependencies `activerecord`, `sqlite3`), no Rails app needed.
7. Packaging: Ruby ≥ 3.1, rubocop, GitHub Actions CI, CHANGELOG, README
   rewritten around the `omniauth-ssoprovider` auth hash above with a
   complete `OmniauthCallbacksController` example (`sync_sso_user`, then
   Devise `sign_in` or session), version 0.2.0.

## Verifying against the hub

There is no hub-side spec for this gem, and there should not be one (it is
client-side). Verify with a fixture auth hash copied from the hub's
`spec/integration/omniauth_ssoprovider_flow_spec.rb` output once TASK-023
lands (the JSON the client app renders in that spec is exactly the auth hash
above). Optionally add an example client app under `examples/` in this repo
that mounts `omniauth-ssoprovider` + `omniauth_syncer` against a running hub
(`SSO_HUB_URL`, client id/secret from the hub admin) as living documentation.

## Definition of done

- Findings 1–6 addressed, suite green, rubocop clean, CI running, README and
  CHANGELOG updated, 0.2.0 built.
- A note back to the hub if the auth hash shape needs anything the hub or the
  strategy does not provide (feeds the hub's TODO.md / the strategy's next
  version).
