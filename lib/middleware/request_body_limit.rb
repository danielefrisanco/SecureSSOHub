require "json"
require "stringio"

# Refuses a request body larger than `max_bytes` on the given paths with 413,
# before Rails reads it: parameter parsing and the request log would
# otherwise parse a JSON document of any size on an unauthenticated endpoint.
# A body without Content-Length (chunked) is read only up to the limit.
class RequestBodyLimit
  # @param app [#call]
  # @param paths [Array<String>] exact PATH_INFO values to guard
  # @param max_bytes [Integer]
  def initialize(app, paths:, max_bytes:)
    @app = app
    @paths = paths
    @max_bytes = max_bytes
  end

  def call(env)
    return @app.call(env) unless guarded?(env["PATH_INFO"])
    return too_large if too_large?(env)

    @app.call(env)
  end

  private

  # The router squeezes repeated slashes and ignores a trailing one, so
  # "//oauth//register/" reaches the same action; compare the same way.
  def guarded?(path)
    normalized = path.to_s.squeeze("/")
    normalized = normalized.delete_suffix("/") unless normalized == "/"
    @paths.include?(normalized)
  end

  def too_large?(env)
    length = env["CONTENT_LENGTH"].to_s
    return length.to_i > @max_bytes unless length.empty?

    body = env["rack.input"]&.read(@max_bytes + 1).to_s
    env["rack.input"] = StringIO.new(body)
    body.bytesize > @max_bytes
  end

  def too_large
    body = { error: "invalid_request", error_description: "request body exceeds #{@max_bytes} bytes" }.to_json
    [413, { "content-type" => "application/json", "cache-control" => "no-store" }, [body]]
  end
end
