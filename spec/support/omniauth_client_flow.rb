require "json"
require "rack/builder"
require "rack/protection"
require "rack/session"
require "rack/test"
require "securerandom"
require "omniauth"
require "omniauth/strategies/ssoprovider"

# A client application built the way omniauth-ssoprovider users build one,
# and the browser that logs a user in through it against the in-process hub
# (TASK-023). For request specs:
#
#   - the client legs run in a Rack::Test session on the client app;
#   - the hub legs (authorize, sign-in, consent) run in the spec's own
#     integration session (`get`, `post`, `follow_redirect!`);
#   - the strategy's back-channel calls (token, userinfo) and anything else a
#     client or resource server fetches from https://hub.test go through
#     WebMock to the hub's whole Rack stack (#route_hub_over_http).
module OmniauthClientFlow
  CLIENT_ORIGIN = "https://client.test".freeze
  CALLBACK_URL = "#{CLIENT_ORIGIN}/auth/ssoprovider/callback".freeze
  HUB_ORIGIN = "https://hub.test".freeze

  # Every https://hub.test request made over the network reaches the hub.
  # WebMock seeds `rack.session` with a plain Hash that rack-session 2 cannot
  # commit; the back channel needs no session, so it is dropped.
  def route_hub_over_http
    hub = ->(env) { Rails.application.call(env.except("rack.session", "rack.session.options")) }
    stub_request(:any, %r{\A#{Regexp.escape(HUB_ORIGIN)}/}).to_rack(hub)
  end

  # The client app: a cookie session, the strategy mounted by CLASS —
  # `provider :ssoprovider` cannot find the class in 0.1.2 (T44, finding 1) —
  # a page handing out OmniAuth 2's request-phase CSRF token, and a callback
  # that renders the auth hash as JSON. The `resource` indicator is host-app
  # configuration because 0.1.2 has no option for it (T44, finding 4).
  #
  # @param client [Doorkeeper::Application] a confidential client registered with CALLBACK_URL
  # @return [#call]
  def omniauth_client_app(client, **strategy_options)
    options = { client_options: { site: HUB_ORIGIN }, scope: "openid profile email", pkce: true,
                authorize_params: { resource: OAuth::Resources.hub_api } }.merge(strategy_options)
    uid = client.uid
    password = client.plaintext_secret
    Rack::Builder.new do
      use Rack::Session::Cookie, secret: SecureRandom.hex(32), same_site: :lax
      use OmniAuth::Builder do
        provider OmniAuth::Strategies::SSOProvider, uid, password, options
      end
      map("/login") do
        run ->(env) { [200, { "content-type" => "text/plain" }, [Rack::Protection::AuthenticityToken.token(env["rack.session"])]] }
      end
      map("/auth/ssoprovider/callback") do
        run ->(env) { [200, { "content-type" => "application/json" }, [JSON.generate(env["omniauth.auth"].to_hash)]] }
      end
    end.to_app
  end

  # @return [Rack::Test::Session] the user's browser on the client side
  def client_browser(app)
    Rack::Test::Session.new(app, "client.test")
  end

  # Client: "Log in with the hub" — OmniAuth 2 only starts on a POST carrying
  # its CSRF token.
  #
  # @return [String] the hub authorization URL the client redirects to
  def start_login(browser)
    browser.get("#{CLIENT_ORIGIN}/login")
    browser.post("#{CLIENT_ORIGIN}/auth/ssoprovider", authenticity_token: browser.last_response.body)
    browser.last_response.location
  end

  # Hub, in the user's browser: open the authorization URL, sign in, then
  # answer the consent page (:allow or :deny).
  #
  # @return [String, nil] where the hub sends the browser back to the client,
  #   or nil when the hub renders an error page itself
  def authorize_at_hub(url, user:, consent: :allow)
    get url
    follow_redirect! # the sign-in page
    post "#{HUB_ORIGIN}/users/sign_in", params: { user: { email: user.email, password: user.password } }
    follow_redirect! # back to /oauth/authorize: the consent page, or an error page
    submit_consent(consent) if response.ok?
    response.location if response.redirect? && response.location.start_with?(CLIENT_ORIGIN)
  end

  # Client: the browser arrives on the callback.
  #
  # @return [Rack::MockResponse]
  def finish_login(browser, callback_url)
    browser.get(callback_url)
    browser.last_response
  end

  private

  def submit_consent(choice)
    # Allow posts to /oauth/authorize; Deny carries _method=delete.
    form = response.parsed_body.css(".consent-actions form").find do |candidate|
      candidate.at_css("input[name=_method][value=delete]").present? == (choice == :deny)
    end
    fields = form.css("input[type=hidden]").to_h { |input| [input["name"], input["value"]] }
    post URI.join(HUB_ORIGIN, form["action"]).to_s, params: fields
  end
end
