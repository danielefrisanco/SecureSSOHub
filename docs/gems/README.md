# Gem handover prompts

One file per self-developed gem. Each file is written to be pasted, as is, into a
Claude session opened **in that gem's repository**. It carries everything that
session needs from the hub side: what the hub emits, what the hub had to work
around, the exact change requested, the tests that prove it, and how to verify
the result against the hub before releasing.

| Gem | Local repo | Version | Priority | File |
|---|---|---|---|---|
| rack-jwt-verifier | `../rack_jwt_verifier` | 0.3.0 | **high** (T52 is a security fix) | [rack-jwt-verifier.md](rack-jwt-verifier.md) |
| omniauth-ssoprovider | `../omniauth-ssoprovider` | 0.1.2 | **high** (README example does not boot) | [omniauth-ssoprovider.md](omniauth-ssoprovider.md) |
| header_guard | `../headerguard` | 0.3.1 | low | [header_guard.md](header_guard.md) |
| jwt_auth_client | `../jwt_auth_client` | 0.2.0 | low (deferred) | [jwt_auth_client.md](jwt_auth_client.md) |
| omniauth_syncer | `../omniauth_syncer` | 0.1.0 | low | [omniauth_syncer.md](omniauth_syncer.md) |

Sources of truth on the hub side (state of `develop` after TASK-020, 2026-09-18):

- Token contract: `docs/ARCHITECTURE.md` §3 (access token claims, id_token, refresh).
- Gem gap register: `TODO.md` rows tagged `[gem: …]` (T12, T40, T44, T45, T46, T48, T52).
- Original per-gem audit: `docs/AUDIT.md` §3 and §9.
- Live proof against real hub tokens: `spec/requests/api/rack_jwt_verifier_interop_spec.rb`,
  `spec/requests/api/v1/userinfo_spec.rb`, `spec/requests/oauth/token_spec.rb`.

Verifying a gem change against the hub before releasing it:

```ruby
# SecureSSOHub/Gemfile (temporarily, never commit)
gem "rack-jwt-verifier", path: "../rack_jwt_verifier"
```

```bash
cd SecureSSOHub && bundle install
POSTGRES_HOST=localhost bundle exec rspec spec/requests/api
```

After a release: bump the version in the hub's `Gemfile`, remove the hub-side
workaround named in the gem's file, and close the matching `TODO.md` row.
