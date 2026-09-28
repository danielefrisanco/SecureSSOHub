# A user's standing permission for a client to act with a set of scopes
# (TASK-018). Written and read through OAuth::Consents — the client side of
# the relation is the authorization server's application record, which the
# service layer resolves from the client_id (docs/ARCHITECTURE.md §4).
class OAuthConsent < ApplicationRecord
  belongs_to :user

  scope :live, -> { where(revoked_at: nil) }

  validates :scopes, presence: true
  validates :granted_at, presence: true

  # @return [Array<String>]
  def scope_list
    scopes.to_s.split
  end

  def scope_list=(names)
    self.scopes = Array(names).map(&:to_s).uniq.join(" ")
  end
end
