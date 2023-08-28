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

-- Adds a few fields to OAuth 2.0 clients, and squash the redirect_uris in the same table

ALTER TABLE "oauth2_clients"
    ADD COLUMN "redirect_uris" TEXT[] NOT NULL DEFAULT '{}',
    ADD COLUMN "application_type" TEXT,
    ADD COLUMN "contacts" TEXT[] NOT NULL DEFAULT '{}';

-- Insert in the new `redirect_uris` column the values from the old table
UPDATE "oauth2_clients"
    SET "redirect_uris" = ARRAY(
        SELECT "redirect_uri"
        FROM "oauth2_client_redirect_uris"
        WHERE "oauth2_client_redirect_uris"."oauth2_client_id" = "oauth2_clients"."oauth2_client_id"
        GROUP BY "redirect_uri"
    );

-- Drop the old table
DROP TABLE "oauth2_client_redirect_uris";