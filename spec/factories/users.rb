FactoryBot.define do
  factory :user do
    sequence(:email) { |n| "user#{n}@example.com" }
    name { "Test User" }
    password { "correct horse battery staple" }

    trait :admin do
      is_admin { true }
    end
  end
end
