# Registered OAuth clients (Doorkeeper::Application with the hub's columns).
# Specs outside app/services/oauth use this factory and OAuth::Clients, never
# the Doorkeeper constant directly.
FactoryBot.define do
  factory :oauth_client, class: "Doorkeeper::Application" do
    sequence(:name) { |n| "Client #{n}" }
    redirect_uri { "https://client.test/callback" }
    scopes { "openid profile" }
    client_type { "confidential" }
    confidential { true }
    approval_state { "approved" }
    registered_via { "admin" }

    trait :public do
      client_type { "public" }
      confidential { false }
      secret { nil }
    end

    trait :pending do
      approval_state { "pending" }
      registered_via { "dynamic" }
    end

    trait :revoked do
      approval_state { "revoked" }
    end
  end
end
