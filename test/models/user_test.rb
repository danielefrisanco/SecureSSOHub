require "test_helper"
require "jwt" # Required to decode and verify the token

class UserTest < ActiveSupport::TestCase
  # This setup creates a mock user before each test run
  setup do
    @user = User.new(email: "test@example.com", password: "password", password_confirmation: "password")
    assert @user.save, "Test user failed to save: #{@user.errors.full_messages.to_sentence}"
  end

  # --- SSO ID TESTS ---

  test "should generate sso_id before creation" do
    assert_not_nil @user.sso_id, "SSO ID should not be nil after creation."
    assert_equal 36, @user.sso_id.length, "SSO ID should be a standard UUID length."
  end

  test "sso_id must be unique" do
    duplicate_user = User.new(email: "duplicate@example.com", password: "password", password_confirmation: "password")
    
    # Manually set the duplicate user's sso_id to the existing user's sso_id
    duplicate_user.sso_id = @user.sso_id
    
    assert_not duplicate_user.valid?, "User should not be valid with a duplicate sso_id."
    assert_includes duplicate_user.errors[:sso_id], "has already been taken"
  end

  # --- JWT GENERATION TESTS ---
  
  test "should generate a signed JWT token" do
    # to_jwt is provided by the JwtAuthClient::Issuable module
    token = @user.to_jwt
    
    # 1. Check if the token is present and has the expected three parts (header.payload.signature)
    assert_not_nil token
    assert_equal 3, token.split('.').length, "JWT must contain three segments separated by dots."

    # 2. Decode the token to verify the content (we must provide the Hub's secret)
    secret = Rails.application.credentials.sso_hub_client_secret
    
    begin
      decoded_token = JWT.decode(token, secret, true, { algorithm: 'HS256' })
      payload = decoded_token.first
      
      # 3. Verify the payload content matches the user data
      assert_equal @user.sso_id, payload['user_id']
      assert_equal @user.email, payload['email']
      assert_equal 'SecuressoHub', payload['iss'], "Issuer claim ('iss') must be correct."
      
      # 4. Verify IAT and EXP claims are present and numeric
      assert_kind_of Integer, payload['iat'], "Issued At Time ('iat') must be an integer timestamp."
      assert_kind_of Integer, payload['exp'], "Expiration Time ('exp') must be an integer timestamp."
      
    rescue JWT::DecodeError => e
      flunk "JWT decoding failed: #{e.message}. The secret or signature is incorrect."
    end
  end
end
