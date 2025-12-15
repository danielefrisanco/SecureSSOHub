class User < ApplicationRecord
  # Include default devise modules. Others available are:
  # :confirmable, :lockable, :timeoutable, :trackable and :omniauthable
  devise :database_authenticatable, :registerable,
         :recoverable, :rememberable, :validatable
         # User model configured with Devise and extended to act as a JWT token issuer.
  
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
  
  private
  
  # Generates a unique UUID if sso_id is not already present.
  # This UUID is the non-email identifier used across all trusting services.
  def set_sso_id
    self.sso_id = SecureRandom.uuid unless self.sso_id.present?
  end

  # REQUIRED BY JWT AUTH CLIENT: Defines the payload (claims) inside the JWT.
  # The SSO Hub signs this payload.
  def jwt_payload
    {
      'user_id' => self.sso_id,
      'email' => self.email,
      'iat' => Time.now.to_i,        # Issued At Time
      'exp' => 1.hour.from_now.to_i, # Expiration Time (Tokens should be short-lived)
      'iss' => 'SecuressoHub'        # Issuer ID (The Hub's ID)
    }
  end

  # REQUIRED BY JWT AUTH CLIENT: Provides the secret key for signing the token.
  def jwt_secret
    # Fetches the secret from the encrypted credentials file.
    Rails.application.credentials.sso_hub_client_secret
  end
end
