class ApplicationMailer < ActionMailer::Base
  # One sender for every mail the hub sends: MAILER_FROM (config/initializers/devise.rb).
  default from: -> { Devise.mailer_sender }
  layout "mailer"
end
