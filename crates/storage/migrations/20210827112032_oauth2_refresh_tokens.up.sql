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

CREATE TABLE oauth2_refresh_tokens (
  "id" BIGSERIAL PRIMARY KEY,
  "oauth2_session_id" BIGINT NOT NULL REFERENCES oauth2_sessions (id) ON DELETE CASCADE,
  "oauth2_access_token_id" BIGINT REFERENCES oauth2_access_tokens (id) ON DELETE SET NULL,

  "token" TEXT UNIQUE NOT NULL,
  "next_token_id" BIGINT REFERENCES oauth2_refresh_tokens (id),

  "created_at" TIMESTAMP WITH TIME ZONE NOT NULL DEFAULT now(),
  "updated_at" TIMESTAMP WITH TIME ZONE NOT NULL DEFAULT now()
);

CREATE TRIGGER set_timestamp
  BEFORE UPDATE ON oauth2_refresh_tokens
  FOR EACH ROW
  EXECUTE PROCEDURE trigger_set_timestamp();
