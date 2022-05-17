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

CREATE TABLE compat_sessions (
  "id" BIGSERIAL PRIMARY KEY,
  "user_id" BIGINT NOT NULL REFERENCES users (id) ON DELETE CASCADE,
  "device_id" TEXT UNIQUE NOT NULL,

  "created_at" TIMESTAMP WITH TIME ZONE NOT NULL DEFAULT now(),
  "deleted_at" TIMESTAMP WITH TIME ZONE
);

INSERT INTO compat_sessions (user_id, device_id, created_at, deleted_at)
  SELECT user_id, device_id, created_at, deleted_at
  FROM compat_access_tokens;

ALTER TABLE compat_access_tokens
  ADD COLUMN "compat_session_id" BIGINT REFERENCES compat_sessions (id) ON DELETE CASCADE;

UPDATE compat_access_tokens
  SET compat_session_id = compat_sessions.id
  FROM compat_sessions
  WHERE compat_sessions.device_id = compat_access_tokens.device_id;

ALTER TABLE compat_access_tokens
  ALTER COLUMN "compat_session_id" SET NOT NULL,
  DROP COLUMN "device_id",
  DROP COLUMN "user_id",
  DROP COLUMN "deleted_at",
  ADD COLUMN "expires_after" INT;

CREATE TABLE compat_refresh_tokens (
  "id" BIGSERIAL PRIMARY KEY,
  "compat_session_id" BIGINT NOT NULL REFERENCES compat_sessions (id) ON DELETE CASCADE,
  "compat_access_token_id" BIGINT REFERENCES compat_access_tokens (id) ON DELETE SET NULL,
  "token" TEXT UNIQUE NOT NULL,
  "next_token_id" BIGINT REFERENCES compat_refresh_tokens (id),
  "created_at" TIMESTAMP WITH TIME ZONE NOT NULL DEFAULT now()
);
