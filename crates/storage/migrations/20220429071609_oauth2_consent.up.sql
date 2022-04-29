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

CREATE TABLE oauth2_consents (
  "id" BIGSERIAL PRIMARY KEY,
  "oauth2_client_id" BIGINT NOT NULL REFERENCES oauth2_clients (id) ON DELETE CASCADE,
  "user_id" BIGINT NOT NULL REFERENCES users (id) ON DELETE CASCADE,
  "scope_token" TEXT NOT NULL,
  "created_at" TIMESTAMP WITH TIME ZONE NOT NULL DEFAULT now(),
  "updated_at" TIMESTAMP WITH TIME ZONE NOT NULL DEFAULT now(),

  CONSTRAINT user_client_scope_tuple UNIQUE ("oauth2_client_id", "user_id", "scope_token")
);

CREATE INDEX oauth2_consents_client_id_user_id_key 
  ON oauth2_consents ("oauth2_client_id", "user_id");

CREATE TRIGGER set_timestamp
  BEFORE UPDATE ON oauth2_consents
  FOR EACH ROW
  EXECUTE PROCEDURE trigger_set_timestamp();
