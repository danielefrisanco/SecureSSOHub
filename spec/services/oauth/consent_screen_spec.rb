require "rails_helper"

# The consent page's wiring into Doorkeeper::AuthorizationsController. The page
# itself is spec/requests/oauth/consent_spec.rb; this guards the boot order.
RSpec.describe OAuth::ConsentScreen do
  # Under eager loading (CI sets CI=true, production) the controller's view
  # class is built before config/initializers/doorkeeper.rb prepends this
  # module; the view must still see the `consent` helper.
  it "exposes consent to the controller's views" do
    view_class = Doorkeeper::AuthorizationsController.view_context_class

    expect(view_class.method_defined?(:consent)).to be(true)
  end
end
