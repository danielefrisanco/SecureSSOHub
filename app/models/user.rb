class User < ApplicationRecord
  # Accounts are created by an admin, so :registerable is deliberately off.
  # :confirmable waits for a configured mailer (its columns already exist).
  devise :database_authenticatable, :recoverable, :rememberable, :validatable,
         :trackable, :lockable, :timeoutable
  
  # === JWT INTEGRATION ===
  
  # Include the Issuable module from the 'jwt_auth_client' gem.
  # This mixin provides the `to_jwt` method, which is implicitly called by the 
  # SSO Hub controller to generate the token for the client app.
  include JwtAuthClient::Issuable 
  
  # Validation to ensure the sso_id is present and unique.
  validates :sso_id, presence: true, uniqueness: true
  
  # Callback to ensure a stable, globally unique ID (sso_id) is set 
  # before the user record is saved.
  before_validation :set_sso_id, on: :create
  
  # Custom claims embedded by JwtAuthClient::Issuable#to_jwt. The registered
  # claims (iss, sub, iat, nbf, exp, jti) are set by the gem from its
  # configuration; `sub` is taken from `user_id`, i.e. the stable sso_id.
  def jwt_claims
    {
      user_id: sso_id,
      email: email,
      name: name,
      admin: is_admin
    }
  end

  private
  
  # Generates a unique UUID if sso_id is not already present.
  # This UUID is the non-email identifier used across all trusting services.
  def set_sso_id
    self.sso_id = SecureRandom.uuid unless self.sso_id.present?
  end

end
