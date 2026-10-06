# Rate limits on Devise's account forms (TASK-028), attached to Devise's
# controllers from config/initializers/rate_limits.rb. Each form is counted
# per address and per submitted email; the email is hashed, so the cache holds
# no address book. A refusal re-renders the form with 429, Retry-After and a
# flash that says nothing about whether the account exists. Rails counts
# nothing when the cache cannot be reached, so a Redis outage locks no one out.
module AccountRateLimits
  extend ActiveSupport::Concern

  class_methods do
    # @param name [String] distinguishes the counters of one form
    # @param limit [Integer] requests per key and window
    # @param within [ActiveSupport::Duration]
    # @param by [Symbol, Proc] the key; the client address by default
    def account_rate_limit(name, limit:, within:, by: -> { request.remote_ip })
      rate_limit(to: limit, within: within, by: by, name: name, only: :create, prepend: true,
                 with: -> { refuse_rate_limited(within) })
    end
  end

  # POST /users/sign_in, per minute. Lockable still locks an account after
  # its failed attempts; this slows the guessing down before that.
  module SignIn
    extend ActiveSupport::Concern
    include AccountRateLimits

    included do
      limits = Rails.configuration.x.rate_limits
      account_rate_limit "address", limit: limits.sign_in, within: 1.minute
      account_rate_limit "email", limit: limits.sign_in_email, within: 1.minute, by: :submitted_email_key
    end
  end

  # POST /users/password, /users/unlock and /users/confirmation, per hour: each
  # sends an email, so unthrottled they would flood someone's inbox.
  module AccountMail
    extend ActiveSupport::Concern
    include AccountRateLimits

    included do
      limits = Rails.configuration.x.rate_limits
      account_rate_limit "address", limit: limits.account_mail, within: 1.hour
      account_rate_limit "email", limit: limits.account_mail_email, within: 1.hour, by: :submitted_email_key
    end
  end

  private

  def submitted_email_key
    fields = params[resource_name]
    email = fields.is_a?(ActionController::Parameters) ? fields[:email] : nil
    Digest::SHA256.hexdigest(email.to_s.strip.downcase)
  end

  def refuse_rate_limited(within)
    response.headers["Retry-After"] = within.to_i.to_s
    self.resource = resource_class.new
    flash.now[:alert] = t("rate_limits.too_many_requests")
    render :new, status: :too_many_requests
  end
end
