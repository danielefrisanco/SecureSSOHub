# Per-request context for the audit log (TASK-029), reset by Rails after
# every request and job. RequestContext (lib/middleware) sets the address and
# request id; a Warden hook (config/initializers/audit.rb) sets the signed-in
# user, who is the actor of whatever the request changes unless the caller
# names one.
class Current < ActiveSupport::CurrentAttributes
  attribute :ip, :request_id, :user
end
