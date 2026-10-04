# Puts the client address and the request id into Current for the audit log
# (TASK-029). Sits after ActionDispatch::RemoteIp, so the address is the one
# Rails trusts (the proxy's own until trusted proxies are configured,
# TASK-033), and before Warden, so sign-in hooks see it too.
class RequestContext
  def initialize(app)
    @app = app
  end

  def call(env)
    request = ActionDispatch::Request.new(env)
    Current.ip = request.remote_ip
    Current.request_id = request.request_id
    @app.call(env)
  end
end
