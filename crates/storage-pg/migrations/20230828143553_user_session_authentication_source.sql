-- Copyright 2023 The Matrix.org Foundation C.I.C.
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

-- This adds the source of each authentication of a user_session
ALTER TABLE "user_session_authentications"
    ADD COLUMN "user_password_id" UUID
        REFERENCES "user_passwords" ("user_password_id")
        ON DELETE SET NULL,

    ADD COLUMN "upstream_oauth_authorization_session_id" UUID
        REFERENCES "upstream_oauth_authorization_sessions" ("upstream_oauth_authorization_session_id")
        ON DELETE SET NULL;