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

--- Adds a table to store device codes for OAuth 2.0 device code flows
--
--
-- This has 4 possible states, only going in one direction:
--
--     [[ Pending ]]
--       |       |
--       |  [ Rejected ] -- The `rejected_at` and `user_session_id` fields are set
--       |   
-- [ Fulfilled ] -- The `fulfilled_at` and `user_session_id` fields are set
--       |
-- [ Exchanged ] -- The `exchanged_at` and `oauth2_session_id` fields are also set
--
CREATE TABLE "oauth2_device_code_grant" (
    "oauth2_device_code_grant_id" UUID NOT NULL
        PRIMARY KEY,

    -- The client who initiated the device code grant
    "oauth2_client_id" UUID NOT NULL
        REFERENCES "oauth2_clients" ("oauth2_client_id")
        ON DELETE CASCADE,

    -- The scope requested
    "scope" TEXT NOT NULL,

    -- The random code that is displayed to the user
    "user_code" TEXT NOT NULL
        UNIQUE,

    -- The random code that the client uses to poll for the access token
    "device_code" TEXT NOT NULL
        UNIQUE,

    -- Timestamp when the device code was created
    "created_at" TIMESTAMP WITH TIME ZONE NOT NULL,

    -- Timestamp when the device code expires
    "expires_at" TIMESTAMP WITH TIME ZONE NOT NULL,

    -- When the device code was fulfilled, i.e. the user has granted access
    -- This is mutually exclusive with rejected_at
    "fulfilled_at" TIMESTAMP WITH TIME ZONE,

    -- When the device code was rejected, i.e. the user has denied access
    -- This is mutually exclusive with fulfilled_at
    "rejected_at" TIMESTAMP WITH TIME ZONE,

    -- When the device code was exchanged
    -- This means "fulfilled_at" has also been set
    "exchanged_at" TIMESTAMP WITH TIME ZONE,

    -- The OAuth 2.0 session generated for this device code
    -- This means "exchanged_at" has also been set
    "oauth2_session_id" UUID
        REFERENCES "oauth2_sessions" ("oauth2_session_id")
        ON DELETE CASCADE,

    -- The browser session ID that the user used to authenticate
    -- This means "fulfilled_at" or "rejected_at" has also been set
    "user_session_id" UUID
        REFERENCES "user_sessions" ("user_session_id"),

    -- The IP address of the user when they authenticated
    "ip_address" INET,

    -- The user agent of the user when they authenticated
    "user_agent" TEXT
);
