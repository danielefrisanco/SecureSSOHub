module OAuth
  # The application's view of registered OAuth clients. This module (and its
  # siblings in app/services/oauth) is the only place that may touch
  # Doorkeeper models — controllers, views, jobs and MCP tools go through it so
  # the authorization-server core can be replaced (docs/ARCHITECTURE.md §4).
  #
  # Create/update/rotate/approve/revoke arrive with TASK-016.
  module Clients
    Client = Struct.new(:uid, :name, :redirect_uris, :scopes, :confidential, :created_at, keyword_init: true)

    module_function

    # @return [Array<Client>] every registered client, newest first.
    def list
      Doorkeeper::Application.order(created_at: :desc).map { |app| wrap(app) }
    end

    # @param uid [String] the public client_id.
    # @return [Client, nil]
    def find(uid)
      app = Doorkeeper::Application.find_by(uid: uid)
      app && wrap(app)
    end

    def wrap(app)
      Client.new(
        uid: app.uid,
        name: app.name,
        redirect_uris: app.redirect_uri.to_s.split,
        scopes: app.scopes.to_a,
        confidential: app.confidential?,
        created_at: app.created_at
      )
    end
    private_class_method :wrap
  end
end
