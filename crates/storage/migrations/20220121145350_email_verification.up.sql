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

CREATE TABLE user_email_verifications (
  "id" BIGSERIAL PRIMARY KEY,
  "user_email_id" BIGINT NOT NULL REFERENCES user_emails (id) ON DELETE CASCADE,
  "code" TEXT UNIQUE NOT NULL,
  "created_at" TIMESTAMP WITH TIME ZONE NOT NULL DEFAULT now(),
  "consumed_at" TIMESTAMP WITH TIME ZONE DEFAULT NULL
);
