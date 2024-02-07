-- Copyright 2024 The Matrix.org Foundation C.I.C.
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

-- Track when users have accepted the terms of service, and which version they accepted.
CREATE TABLE user_terms (
    "user_terms_id" UUID NOT NULL
        PRIMARY KEY,

    -- The user who accepted the terms of service.
    "user_id" UUID NOT NULL
        REFERENCES users (user_id) ON DELETE CASCADE,

    -- The URL of the terms of service that the user accepted.
    "terms_url" TEXT NOT NULL,

    -- When the user accepted the terms of service.
    "created_at" TIMESTAMP WITH TIME ZONE NOT NULL,

    -- Unique constraint to ensure that a user can only accept a given version of the terms once.
    UNIQUE ("user_id", "terms_url")
);
