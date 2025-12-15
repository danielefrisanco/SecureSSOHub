# README

This project is a Ruby on Rails application called "Secure SSO Hub." It's designed to act as a central Single Sign-On (SSO) provider using JWT (JSON Web Tokens).

Here’s a breakdown of its architecture:

Core Framework: It's a standard Ruby on Rails application.
User Authentication: It uses the devise gem to manage its own users (email and password).
SSO Provider: It uses omniauth and omniauth-ssoprovider to allow other applications to use it for authentication.
Identity: Each user has a unique sso_id (a UUID), which is used as the main identifier in the JWT. This is a good practice as it decouples the user's identity from their email address, which might change.
Token Generation: The jwt_auth_client gem is used to create and sign the JWTs.
## The SSO flow is as follows:

1. A client application redirects a user to the Secure SSO Hub.
2. The Hub uses Devise to make sure the user is logged in.
3. Once logged in, the Hub generates a JWT containing the user's sso_id.
4. The Hub redirects the user back to the client application with the JWT.

The project is still incomplete.


---------
---------
---------
---------
---------
---------





























Part 2: What Needs to be Done to Complete the Secure SSO Hub
Now that we have the environment configuration and the underlying JWT logic ready, here are the remaining major tasks to complete the Secure SSO Hub, grouped by priority:

Phase 1: Finish Backend Authentication & Testing (High Priority)
Re-run Docker Build/Up: Try the command again (using the alias or the override you chose) to ensure the build succeeds with the fixed initializer.

Bash

docker compose up -d --build

Run Migrations: If the build is successful, you must migrate the database (which includes the sso_id column).

Bash

docker compose exec web bin/rails db:migrate

Run Tests: Run the model test to verify the UUID and JWT generation logic.

Bash

docker compose exec web bin/rails test test/models/user_test.rb

Implement SSO Provider Strategy: Although you are using the omniauth-ssoprovider gem, the actual strategy logic that turns the incoming request into a user session needs to be implemented. This typically involves making an HTTP request back to the SSO Hub to exchange the authorization code for a JWT, and then verifying the JWT.

Phase 2: Implement Client-Side E2E Security (Medium Priority)
This is the next feature you mentioned—the Vue.js library.

Develop Vue.js securee2e Library: Create the Vue.js library to perform Diffie-Hellman Key Exchange using the Web Cryptography API, along with unit tests, as per your original plan. This library will be used by the front-end to negotiate an ephemeral session key with the Rails backend before sending sensitive data.

Phase 3: Final Backend & Frontend Integration (Low Priority)
Implement Header Guard Logic: Use the header_guard gem to implement server-side verification checks (e.g., checking for the expected public key or session ID) on specific API endpoints before processing requests.

Integrate securee2e in Frontend: Integrate the Vue.js library into the main application's frontend pages to secure all sensitive API calls.

Let's focus on Phase 1 (Steps 1, 2, and 3) first. Once the build and tests pass, we'll have a fully confirmed backend ready for the E2E encryption work. Please run the build command again with the updated initializer file!