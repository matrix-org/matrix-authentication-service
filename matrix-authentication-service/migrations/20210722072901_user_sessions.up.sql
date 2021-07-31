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

-- A logged in session
CREATE TABLE user_sessions (
  "id" BIGSERIAL PRIMARY KEY,
  "user_id" BIGINT NOT NULL REFERENCES users (id) ON DELETE CASCADE,
  "active" BOOLEAN NOT NULL DEFAULT TRUE,

  "created_at" TIMESTAMP WITH TIME ZONE NOT NULL DEFAULT now(),
  "updated_at" TIMESTAMP WITH TIME ZONE NOT NULL DEFAULT now()
);

CREATE TRIGGER set_timestamp
  BEFORE UPDATE ON user_sessions
  FOR EACH ROW
  EXECUTE PROCEDURE trigger_set_timestamp();

-- An authentication within a session
CREATE TABLE user_session_authentications (
  "id" BIGSERIAL PRIMARY KEY,
  "session_id" BIGINT NOT NULL REFERENCES user_sessions (id) ON DELETE CASCADE,
  "created_at" TIMESTAMP WITH TIME ZONE NOT NULL DEFAULT now()
);
