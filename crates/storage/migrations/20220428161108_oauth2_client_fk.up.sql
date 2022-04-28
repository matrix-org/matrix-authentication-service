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

TRUNCATE TABLE oauth2_sessions, oauth2_authorization_grants RESTART IDENTITY CASCADE;

ALTER TABLE oauth2_sessions
  DROP COLUMN "client_id",
  ADD COLUMN "oauth2_client_id" BIGINT 
    NOT NULL
    REFERENCES oauth2_clients (id) ON DELETE CASCADE;

ALTER TABLE oauth2_authorization_grants
  DROP COLUMN "client_id",
  ADD COLUMN "oauth2_client_id" BIGINT
    NOT NULL 
    REFERENCES oauth2_clients (id) ON DELETE CASCADE;
