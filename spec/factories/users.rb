FactoryBot.define do
  factory :user do
    sequence(:email) { |n| "user#{n}@example.com" }
    name { "Test User" }
    password { "correct horse battery staple" }
    # Confirmed, as an account that can sign in must be (:confirmable).
    confirmed_at { Time.current }

    trait :unconfirmed do
      confirmed_at { nil }
    end

    trait :admin do
      is_admin { true }
    end
  end
end
