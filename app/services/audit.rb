# The audit log's only writer (TASK-029). Every hook point in the app calls
# `Audit.record` with what happened, to whom and through which client; the
# address and request id come from Current (RequestContext), the actor is the
# signed-in user unless the caller names one.
#
# Failing closed: a write that fails raises. The hooks that change the
# database record inside the same transaction, so the change and its event
# commit together or not at all; the request fails rather than go unrecorded.
#
# Never pass a token, code, client secret or password: tokens are identified
# by their `jti`. As a second line of defence, metadata keys matching
# `filter_parameters` (config/initializers/filter_parameter_logging.rb) are
# stored as "[FILTERED]".
module Audit
  module_function

  # @param event [String] one of AuditEvent::EVENTS
  # @param actor [User, nil] who did it; the signed-in user by default
  # @param subject_id [Integer, nil] the user the event is about
  # @param client_uid [String, nil] the client involved (the token's `azp`)
  # @param jti [String, nil] the access token involved, by its `jti`
  # @param metadata [Hash] details (scopes, counts, reasons) — never credentials
  # @return [AuditEvent]
  # @raise [ActiveRecord::RecordInvalid] unknown event
  # @raise [ActiveRecord::ActiveRecordError] the event could not be written
  def record(event, actor: Current.user, subject_id: nil, client_uid: nil, jti: nil, **metadata)
    AuditEvent.create!(
      event: event, actor_id: actor&.id, subject_id: subject_id, client_uid: client_uid, jti: jti,
      ip: Current.ip, request_id: Current.request_id, metadata: filter(metadata.compact)
    )
  end

  def filter(metadata)
    ActiveSupport::ParameterFilter.new(Rails.application.config.filter_parameters).filter(metadata)
  end
  private_class_method :filter
end
