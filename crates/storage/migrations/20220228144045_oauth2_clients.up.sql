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

CREATE TABLE oauth2_clients (
  "id" BIGSERIAL PRIMARY KEY,
  "client_id" TEXT NOT NULL UNIQUE,
  "encrypted_client_secret" TEXT,
  "response_types" TEXT[] NOT NULL,
  "grant_type_authorization_code" BOOL NOT NULL,
  "grant_type_refresh_token" BOOL NOT NULL,
  "contacts" TEXT[] NOT NULL,
  "client_name" TEXT,
  "logo_uri" TEXT,
  "client_uri" TEXT,
  "policy_uri" TEXT,
  "tos_uri" TEXT,
  "jwks_uri" TEXT,
  "jwks" JSONB,
  "id_token_signed_response_alg" TEXT,
  "token_endpoint_auth_method" TEXT,
  "token_endpoint_auth_signing_alg" TEXT,
  "initiate_login_uri" TEXT,

  "created_at" TIMESTAMP WITH TIME ZONE NOT NULL DEFAULT now(),
  "updated_at" TIMESTAMP WITH TIME ZONE NOT NULL DEFAULT now(),

  -- jwks and jwks_uri can't be set at the same time
  CHECK ("jwks" IS NULL OR "jwks_uri" IS NULL)
);

CREATE TRIGGER set_timestamp
  BEFORE UPDATE ON oauth2_clients
  FOR EACH ROW
  EXECUTE PROCEDURE trigger_set_timestamp();

CREATE TABLE oauth2_client_redirect_uris (
  "id" BIGSERIAL PRIMARY KEY,
  "oauth2_client_id" BIGINT NOT NULL REFERENCES oauth2_clients (id) ON DELETE CASCADE,
  "redirect_uri" TEXT NOT NULL
);
