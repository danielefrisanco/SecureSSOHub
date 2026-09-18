class User < ApplicationRecord
  # Accounts are created by an admin, so :registerable is deliberately off.
  # :confirmable waits for a configured mailer (its columns already exist).
  devise :database_authenticatable, :recoverable, :rememberable, :validatable,
         :trackable, :lockable, :timeoutable

  # Validation to ensure the sso_id is present and unique.
  validates :sso_id, presence: true, uniqueness: true

  # Callback to ensure a stable, globally unique ID (sso_id) is set
  # before the user record is saved.
  before_validation :set_sso_id, on: :create

  private

  # Generates a unique UUID if sso_id is not already present.
  # This UUID is the non-email identifier used across all trusting services.
  def set_sso_id
    self.sso_id = SecureRandom.uuid unless sso_id.present?
  end
end
