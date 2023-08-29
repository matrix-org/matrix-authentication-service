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

-- We need to be able to do OAuth 2.0 sessions without a user session,
-- and we would like to find sessions with a particular scope.
--
-- This migration edits the "oauth2_sessions" table to:
--  * Add a "user_id" column
--  * Make the "user_session_id" nullable
--  * Infer the "user_id" from the "user_session_id" for existing rows
--  * Add a "scope_list" column, which is the "scope" column in array form
--  * Import the "scope" column into the "scope_list" column for existing rows by splitting on spaces
--  * Sets both columns as NOT NULL once the migration is complete
--  * Drop the "scope" column
--  * Index the "scope_list" column with a GIN index

ALTER TABLE "oauth2_sessions"
    ADD COLUMN "user_id" UUID
        REFERENCES "users" ("user_id") ON DELETE CASCADE,
    ADD COLUMN "scope_list" TEXT[];

UPDATE "oauth2_sessions"
    SET "user_id" = "user_sessions"."user_id"
    FROM "user_sessions"
    WHERE "oauth2_sessions"."user_session_id" = "user_sessions"."user_session_id";

UPDATE "oauth2_sessions"
    SET "scope_list" = string_to_array("scope", ' ')
    WHERE "scope_list" IS NULL;

ALTER TABLE "oauth2_sessions"
    ALTER COLUMN "user_session_id" DROP NOT NULL,
    ALTER COLUMN "user_id" SET NOT NULL,
    ALTER COLUMN "scope_list" SET NOT NULL,
    DROP COLUMN "scope";

CREATE INDEX "oauth2_sessions_scope_list_idx"
    ON "oauth2_sessions" USING GIN ("scope_list");