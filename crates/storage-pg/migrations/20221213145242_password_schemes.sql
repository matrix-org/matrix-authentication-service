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

ALTER TABLE "user_passwords"
  ADD COLUMN "version" INTEGER NOT NULL DEFAULT 1,
  ADD COLUMN "upgraded_from_id" UUID
    CONSTRAINT "user_passwords_upgraded_from_id_fkey"
    REFERENCES "user_passwords" ("user_password_id")
    ON DELETE SET NULL;

-- Remove the default after creating the column
ALTER TABLE "user_passwords"
  ALTER COLUMN "version" DROP DEFAULT;
