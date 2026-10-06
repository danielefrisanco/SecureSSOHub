require "rails_helper"

# Each service-level hook point of the audit log (TASK-029) records its event:
# the client registry, token revocation, consents and account changes. The
# HTTP-level ones (sign-in, token issuance, the revocation endpoint) are in
# spec/requests/audit_log_spec.rb.
RSpec.describe "Audit log hook points" do
  let(:admin) { create(:user, :admin) }
  let(:user) { create(:user) }
  let(:client) { create(:oauth_client) }

  def last_event(name)
    AuditEvent.where(event: name).order(:id).last
  end

  def token_for(owner, app = client, **attributes)
    Doorkeeper::AccessToken.create!(application: app, resource_owner_id: owner.id, scopes: "openid", expires_in: 600,
                                    **attributes)
  end

  describe "OAuth::Clients" do
    let(:attributes) do
      { name: "Billing", redirect_uris: ["https://billing.test/cb"], client_type: :confidential, scopes: %w[openid] }
    end

    it "records an administrator's registration, without the secret" do
      registration = OAuth::Clients.create(**attributes, by: admin)

      event = last_event("client.created")
      expect(event).to have_attributes(actor_id: admin.id, client_uid: registration.client.uid)
      expect(event.metadata).to include("name" => "Billing", "client_type" => "confidential",
                                        "redirect_uris" => ["https://billing.test/cb"], "scopes" => %w[openid],
                                        "approval_state" => "approved")
      expect(event.attributes.to_json).not_to include(registration.secret)
    end

    it "records a dynamic registration with no actor and the requester's address" do
      registration = Current.set(ip: "198.51.100.7", user: admin) do
        OAuth::Clients.register_dynamic(**attributes, client_type: :public, policy: :approval,
                                                      registration_ip: "198.51.100.7")
      end

      expect(last_event("client.registered")).to have_attributes(actor_id: nil, client_uid: registration.client.uid,
                                                                 ip: IPAddr.new("198.51.100.7"))
      expect(last_event("client.registered").metadata).to include("approval_state" => "pending")
    end

    it "records an update with the changed fields" do
      OAuth::Clients.update(client.uid, by: admin, name: "Renamed", redirect_uris: ["https://new.test/cb"])

      event = last_event("client.updated")
      expect(event).to have_attributes(actor_id: admin.id, client_uid: client.uid)
      expect(event.metadata).to include("name" => "Renamed", "redirect_uris" => ["https://new.test/cb"])
      expect(event.metadata["fields"]).to include("name", "redirect_uri")
    end

    it "records a rotation, without either secret" do
      old_secret = client.plaintext_secret
      rotated = OAuth::Clients.rotate_secret(client.uid, by: admin)

      event = last_event("client.secret_rotated")
      expect(event).to have_attributes(actor_id: admin.id, client_uid: client.uid)
      expect(event.attributes.to_json).not_to include(rotated.secret, old_secret)
    end

    it "records an approval with the state it left" do
      pending_client = create(:oauth_client, :pending)
      OAuth::Clients.approve(pending_client.uid, by: admin)

      expect(last_event("client.approved")).to have_attributes(actor_id: admin.id, client_uid: pending_client.uid)
      expect(last_event("client.approved").metadata).to include("from" => "pending")
    end

    it "records a revocation and the tokens it revoked, both by the administrator" do
      token_for(user)
      OAuth::Clients.revoke(client.uid, by: admin)

      expect(last_event("client.revoked")).to have_attributes(actor_id: admin.id, client_uid: client.uid)
      expect(last_event("tokens.revoked_for_client")).to have_attributes(actor_id: admin.id, client_uid: client.uid)
      expect(last_event("tokens.revoked_for_client").metadata).to include("revoked" => 1)
    end
  end

  describe "OAuth::Tokens" do
    it "records a revocation by the token's owner, with the jti and its family" do
      token = token_for(user)
      OAuth::Tokens.revoke(token.jti, by: user)

      expect(last_event("token.revoked")).to have_attributes(actor_id: user.id, subject_id: user.id,
                                                             client_uid: client.uid, jti: token.jti)
      expect(last_event("token.revoked").metadata).to include("revoked" => 1)
    end

    it "records nothing for a token the caller may not revoke" do
      OAuth::Tokens.revoke(token_for(user).jti, by: create(:user))
      expect(last_event("token.revoked")).to be_nil
    end

    it "records sign out everywhere" do
      token_for(user)
      Current.set(user: admin) { OAuth::Tokens.revoke_all_for(user: user) }

      expect(last_event("tokens.revoked_for_user")).to have_attributes(actor_id: admin.id, subject_id: user.id)
      expect(last_event("tokens.revoked_for_user").metadata).to include("revoked" => 1)
    end

    it "records the revocation of one client's tokens for one user" do
      token_for(user)
      OAuth::Tokens.revoke_for(user: user, client_uid: client.uid, actor: user)

      expect(last_event("tokens.revoked_for_user_and_client")).to have_attributes(
        actor_id: user.id, subject_id: user.id, client_uid: client.uid
      )
    end
  end

  describe "OAuth::Consents" do
    it "records a new consent and a widened one, not a repeat" do
      OAuth::Consents.grant(user: user, client_uid: client.uid, scopes: %w[openid])
      OAuth::Consents.grant(user: user, client_uid: client.uid, scopes: %w[openid])
      OAuth::Consents.grant(user: user, client_uid: client.uid, scopes: %w[openid profile])

      events = AuditEvent.where(event: "consent.granted").order(:id)
      expect(events.map(&:metadata)).to eq([{ "scopes" => %w[openid], "added" => %w[openid] },
                                            { "scopes" => %w[openid profile], "added" => %w[profile] }])
      expect(events.map { |event| [event.actor_id, event.subject_id, event.client_uid] }.uniq)
        .to eq([[user.id, user.id, client.uid]])
    end

    it "records a revocation and the tokens it took with it" do
      OAuth::Consents.grant(user: user, client_uid: client.uid, scopes: %w[openid])
      token_for(user)
      Current.set(user: user) { OAuth::Consents.revoke(user: user, client_uid: client.uid) }

      expect(last_event("consent.revoked")).to have_attributes(actor_id: user.id, subject_id: user.id,
                                                               client_uid: client.uid)
      expect(last_event("tokens.revoked_for_user_and_client").metadata).to include("revoked" => 1)
    end
  end

  describe "User" do
    it "records a password change and the sign out everywhere it causes" do
      user.update!(password: "a different passphrase")

      expect(last_event("user.password_changed")).to have_attributes(subject_id: user.id)
      expect(last_event("tokens.revoked_for_user")).to have_attributes(subject_id: user.id)
    end

    it "records an administrator disabling the account" do
      Current.set(user: admin) { user.update!(disabled_at: Time.current) }
      expect(last_event("user.disabled")).to have_attributes(actor_id: admin.id, subject_id: user.id)
    end

    it "records a failed-attempts lock, with no actor" do
      user.update!(failed_attempts: 5)
      user.lock_access!(send_instructions: false)

      expect(last_event("user.locked")).to have_attributes(actor_id: nil, subject_id: user.id)
      expect(last_event("user.locked").metadata).to include("failed_attempts" => 5)
    end

    it "records an email confirmation, with no actor when the user follows the link" do
      unconfirmed = create(:user, :unconfirmed)
      unconfirmed.confirm

      expect(last_event("user.email_confirmed")).to have_attributes(actor_id: nil, subject_id: unconfirmed.id)
      expect(last_event("user.email_confirmed").metadata).to eq("reconfirmation" => false)
    end

    it "records nothing for a profile change" do
      user.update!(name: "Renamed")
      expect(AuditEvent.where(subject_id: user.id)).to be_empty
    end
  end
end
