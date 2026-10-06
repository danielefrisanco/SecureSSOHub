module OAuth
  # Rails' `rate_limit` for the hub's OAuth endpoints (TASK-028) with an
  # RFC 6749-style refusal: 429 `temporarily_unavailable`, `Retry-After` set
  # to the window (the longest a client can have to wait) and no-store.
  # Counters live in the shared cache (TASK-027). When the cache cannot be
  # reached Rails counts nothing and lets the request through: a Redis outage
  # must not take token issuance down with it (readiness reports it, TASK-033).
  # The limits run before the controller's own callbacks, so a request that
  # would be refused for another reason is counted too.
  module EndpointRateLimits
    extend ActiveSupport::Concern

    class_methods do
      # @param action [Symbol] the controller action
      # @param limit [Integer] requests per key and window
      # @param within [ActiveSupport::Duration]
      # @param options [Hash] passed on to rate_limit (`by:`, `if:`)
      def oauth_rate_limit(action, limit:, within:, **)
        rate_limit(to: limit, within: within, name: action.to_s, only: action, prepend: true,
                   with: -> { refuse_rate_limited(within) }, **)
      end
    end

    private

    def refuse_rate_limited(within)
      response.headers["Retry-After"] = within.to_i.to_s
      response.headers["Cache-Control"] = "no-store"
      render json: { error: "temporarily_unavailable", error_description: "too many requests; try again later" },
             status: :too_many_requests
    end
  end
end
