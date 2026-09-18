# The Content Security Policy is set here, not by header_guard, for one reason:
# `javascript_importmap_tags` emits an inline <script type="importmap"> and an
# inline module script, so an enforced policy needs a per-request nonce.
# header_guard 0.3.1 only takes a static policy string, so it would force
# 'unsafe-inline' — see TODO T46 for the gem-side follow-up. Rails generates the
# nonce, stamps it on those tags and publishes it through `csp_meta_tag` in the
# layout, which is also where Turbo reads it from.
#
# Every other security header (HSTS, frame, referrer, COOP/CORP, permissions)
# comes from header_guard: see config/initializers/header_guard.rb.
Rails.application.configure do
  config.content_security_policy do |policy|
    policy.default_src     :self
    policy.base_uri        :self
    policy.font_src        :self
    policy.form_action     :self
    policy.frame_ancestors :none
    policy.img_src         :self, :data
    policy.object_src      :none
    policy.connect_src     :self
    policy.script_src      :self
    policy.style_src       :self
    policy.upgrade_insecure_requests true if Rails.env.production?
  end

  # A fresh nonce per request rather than one per session: a leaked page source
  # then only ever exposes a nonce that is already spent.
  config.content_security_policy_nonce_generator = ->(_request) { SecureRandom.base64(16) }
  config.content_security_policy_nonce_directives = %w[script-src]
end
