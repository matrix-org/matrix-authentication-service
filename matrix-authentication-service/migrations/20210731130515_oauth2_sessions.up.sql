-- Copyright 2021 The Matrix.org Foundation C.I.C.
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

CREATE TABLE oauth2_sessions (
  "id" BIGSERIAL PRIMARY KEY,
  "user_session_id" BIGINT REFERENCES user_sessions (id) ON DELETE CASCADE,
  "client_id" TEXT NOT NULL,
  "redirect_uri" TEXT NOT NULL,
  "scope" TEXT NOT NULL,
  "state" TEXT,
  "nonce" TEXT,
  "max_age" INT,
  "response_type" TEXT NOT NULL,
  "response_mode" TEXT NOT NULL,

  "created_at" TIMESTAMP WITH TIME ZONE NOT NULL DEFAULT now(),
  "updated_at" TIMESTAMP WITH TIME ZONE NOT NULL DEFAULT now()
);

CREATE TRIGGER set_timestamp
  BEFORE UPDATE ON oauth2_sessions
  FOR EACH ROW
  EXECUTE PROCEDURE trigger_set_timestamp();

CREATE TABLE oauth2_codes (
  "id" BIGSERIAL PRIMARY KEY,
  "oauth2_session_id" BIGINT NOT NULL REFERENCES oauth2_sessions (id) ON DELETE CASCADE,
  "code" TEXT UNIQUE NOT NULL,
  "code_challenge_method" SMALLINT,
  "code_challenge" TEXT,

  CHECK (("code_challenge" IS NULL     AND "code_challenge_method" IS NULL)
      OR ("code_challenge" IS NOT NULL AND "code_challenge_method" IS NOT NULL))
);
