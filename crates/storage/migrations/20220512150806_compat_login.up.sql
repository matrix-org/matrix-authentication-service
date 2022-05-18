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

CREATE TABLE compat_access_tokens (
  "id" BIGSERIAL PRIMARY KEY,
  "compat_session_id" BIGINT NOT NULL REFERENCES compat_sessions (id) ON DELETE CASCADE,
  "token" TEXT UNIQUE NOT NULL,

  "created_at" TIMESTAMP WITH TIME ZONE NOT NULL DEFAULT now(),
  "expires_at" TIMESTAMP WITH TIME ZONE
);

CREATE TABLE compat_refresh_tokens (
  "id" BIGSERIAL PRIMARY KEY,
  "compat_session_id" BIGINT NOT NULL REFERENCES compat_sessions (id) ON DELETE CASCADE,
  "compat_access_token_id" BIGINT REFERENCES compat_access_tokens (id) ON DELETE SET NULL,

  "token" TEXT UNIQUE NOT NULL,
  "next_token_id" BIGINT REFERENCES compat_refresh_tokens (id),

  "created_at" TIMESTAMP WITH TIME ZONE NOT NULL DEFAULT now()
);
