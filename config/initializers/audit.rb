require_relative "../../lib/middleware/request_context"

# The audit log (TASK-029): request context for Audit.record, and the
# sign-in, sign-out and failed sign-in events, which Warden sees first. The
# other hook points call Audit.record themselves (docs/ARCHITECTURE.md §4).
Rails.application.config.middleware.insert_after ActionDispatch::RemoteIp, RequestContext

Rails.application.config.after_initialize do
  # Every time Warden puts a user on the request — signing in, or reading the
  # session — that user becomes the actor of what the request changes.
  # Signing in (a strategy, or Devise's sign_in after a password reset) is
  # recorded; reading the session (:fetch) is not. Devise's own hooks may run
  # after this one and refuse an inactive account (locked), so that case is
  # left to the failure hook.
  Warden::Manager.after_set_user(scope: :user) do |user, auth, opts|
    Current.user = user
    next if opts[:event] == :fetch || !user.active_for_authentication?

    # database_authenticatable (the form) or rememberable (the cookie); none
    # when Devise signs the user in itself.
    strategy = auth.winning_strategy
    Audit.record("user.signed_in", actor: user, subject_id: user.id,
                                   strategy: strategy && strategy.class.name.demodulize.underscore)
  end

  # A sign-in attempt that failed: wrong password, unknown email, locked
  # account. Only the form's POST is an attempt — a page that requires a
  # signed-in user fails the same way. The account is named only when the
  # email matches one; what was typed is never stored (people type passwords
  # into the email field). Warden has already pointed PATH_INFO at the failure
  # app; the path that failed is `attempted_path`.
  Warden::Manager.before_failure(scope: :user) do |env, opts|
    request = ActionDispatch::Request.new(env)
    attempted_path = opts[:attempted_path].to_s.split("?").first
    next unless request.post? && attempted_path == Rails.application.routes.url_helpers.user_session_path

    fields = request.params["user"]
    email = fields.is_a?(Hash) ? fields["email"].to_s : ""
    user = email.present? ? User.find_for_authentication(email: email) : nil
    Audit.record("user.sign_in_failed", actor: nil, subject_id: user&.id, reason: opts[:message]&.to_s)
  end

  Warden::Manager.before_logout(scope: :user) do |user, _auth, _opts|
    next unless user

    Audit.record("user.signed_out", actor: user, subject_id: user.id)
    Current.user = nil
  end
end
