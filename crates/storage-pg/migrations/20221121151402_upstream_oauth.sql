-- Copyright 2022 The Matrix.org Foundation C.I.C.
--
-- Licensed under the Apache License, Version 2.0 (the "License");
-- you may not use this file except in compliance with the License.
-- You may obtain a copy of the License at
--
--     http://www.apache.org/licenses/LICENSE-2.0
--
-- Unless required by applicable law or agreed to in writing, software
-- distributed under the License is distributed on an "AS IS" BASIS,
-- WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
-- See the License for the specific language governing permissions and
-- limitations under the License.

CREATE TABLE "upstream_oauth_providers" (
  "upstream_oauth_provider_id" UUID NOT NULL
    CONSTRAINT "upstream_oauth_providers_pkey"
    PRIMARY KEY,

  "issuer" TEXT NOT NULL,

  "scope" TEXT NOT NULL,

  "client_id" TEXT NOT NULL,

  -- Used for client_secret_basic, client_secret_post and client_secret_jwt auth methods
  "encrypted_client_secret" TEXT,

  -- Used for client_secret_jwt and private_key_jwt auth methods
  "token_endpoint_signing_alg" TEXT,

  "token_endpoint_auth_method" TEXT NOT NULL,

  "created_at" TIMESTAMP WITH TIME ZONE NOT NULL
);

CREATE TABLE "upstream_oauth_links" (
  "upstream_oauth_link_id" UUID NOT NULL
    CONSTRAINT "upstream_oauth_links_pkey"
    PRIMARY KEY,

  "upstream_oauth_provider_id" UUID NOT NULL
    CONSTRAINT "upstream_oauth_links_provider_fkey"
    REFERENCES "upstream_oauth_providers" ("upstream_oauth_provider_id"),

  -- The user is initially NULL when logging in the first time.
  -- It then either links to an existing account, or creates a new one from scratch.
  "user_id" UUID
    CONSTRAINT "upstream_oauth_link_user_fkey"
    REFERENCES "users" ("user_id"),

  "subject" TEXT NOT NULL,

  "created_at" TIMESTAMP WITH TIME ZONE NOT NULL,

  -- There should only be one entry per subject/provider tuple
  CONSTRAINT "upstream_oauth_links_subject_unique"
    UNIQUE ("upstream_oauth_provider_id", "subject")
);

CREATE TABLE "upstream_oauth_authorization_sessions" (
  "upstream_oauth_authorization_session_id" UUID NOT NULL
    CONSTRAINT "upstream_oauth_authorization_sessions_pkey"
    PRIMARY KEY,

  "upstream_oauth_provider_id" UUID NOT NULL
    CONSTRAINT "upstream_oauth_authorization_sessions_provider_fkey"
    REFERENCES "upstream_oauth_providers" ("upstream_oauth_provider_id"),

  -- The link it resolves to at the end of the authorization grant
  "upstream_oauth_link_id" UUID
    CONSTRAINT "upstream_oauth_authorization_sessions_link_fkey"
    REFERENCES "upstream_oauth_links" ("upstream_oauth_link_id"),

  -- The ID token we got at the end of the authorization grant
  "id_token" TEXT,

  "state" TEXT NOT NULL
    CONSTRAINT "upstream_oauth_authorization_sessions_state_unique"
    UNIQUE,

  "code_challenge_verifier" TEXT,
  "nonce" TEXT NOT NULL,

  "created_at" TIMESTAMP WITH TIME ZONE NOT NULL,

  -- When the session turned into a link
  "completed_at" TIMESTAMP WITH TIME ZONE,
  -- When the session turned into a user session authentication
  "consumed_at" TIMESTAMP WITH TIME ZONE
);
