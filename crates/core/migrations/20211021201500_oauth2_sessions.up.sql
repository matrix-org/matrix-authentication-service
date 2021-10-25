-- Copyright 2021 The Matrix.org Foundation C.I.C.
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


-- Replace the old "sessions" table
ALTER TABLE oauth2_sessions RENAME TO oauth2_sessions_old;

-- TODO: how do we handle temporary session upgrades (aka. sudo mode)?
CREATE TABLE oauth2_sessions (
  "id" BIGSERIAL PRIMARY KEY,
  "user_session_id" BIGINT NOT NULL REFERENCES user_sessions (id) ON DELETE CASCADE,
  "client_id" TEXT NOT NULL, -- The "authorization party" would be more accurate in that case
  "scope" TEXT NOT NULL,

  "created_at" TIMESTAMP WITH TIME ZONE NOT NULL DEFAULT now()
);

TRUNCATE oauth2_access_tokens, oauth2_refresh_tokens;
ALTER TABLE oauth2_access_tokens
  DROP CONSTRAINT oauth2_access_tokens_oauth2_session_id_fkey,
  ADD CONSTRAINT oauth2_access_tokens_oauth2_session_id_fkey
    FOREIGN KEY (oauth2_session_id) REFERENCES oauth2_sessions (id);
ALTER TABLE oauth2_refresh_tokens
  DROP CONSTRAINT oauth2_refresh_tokens_oauth2_session_id_fkey,
  ADD CONSTRAINT oauth2_refresh_tokens_oauth2_session_id_fkey
    FOREIGN KEY (oauth2_session_id) REFERENCES oauth2_sessions (id);
DROP TABLE oauth2_codes, oauth2_sessions_old;

CREATE TABLE oauth2_authorization_grants (
  "id" BIGSERIAL PRIMARY KEY, -- Saved as encrypted cookie

  -- All this comes from the authorization request
  "client_id" TEXT NOT NULL, -- This should be verified before insertion
  "redirect_uri" TEXT NOT NULL, -- This should be verified before insertion
  "scope" TEXT NOT NULL, -- This should be verified before insertion
  "state" TEXT,
  "nonce" TEXT,
  "max_age" INT CHECK ("max_age" IS NULL OR "max_age" > 0),
  "acr_values" TEXT, -- This should be verified before insertion
  "response_mode" TEXT NOT NULL,
  "code_challenge_method" TEXT,
  "code_challenge" TEXT,

  -- The "response_type" parameter broken down
  "response_type_code"     BOOLEAN NOT NULL,
  "response_type_token"    BOOLEAN NOT NULL,
  "response_type_id_token" BOOLEAN NOT NULL,

  -- This one is created eagerly on grant creation if the response_type
  -- includes "code"
  -- When looking up codes, it should do "where fulfilled_at is not null" and
  -- "inner join on oauth2_sessions". When doing that, it should check the
  -- "exchanged_at" field: if it is not null and was exchanged more than 30s
  -- ago, the session shold be considered as hijacked and fully invalidated
  "code" TEXT UNIQUE,

  "created_at"   TIMESTAMP WITH TIME ZONE NOT NULL DEFAULT now(),
  "fulfilled_at" TIMESTAMP WITH TIME ZONE, -- When we got back to the client
  "cancelled_at" TIMESTAMP WITH TIME ZONE, -- When that grant was cancelled
  "exchanged_at" TIMESTAMP WITH TIME ZONE, -- When the code was exchanged by the client

  "oauth2_session_id" BIGINT REFERENCES oauth2_sessions (id) ON DELETE CASCADE,

  -- Check a few invariants to keep a coherent state.
  -- Even though the service should never violate those, it helps ensuring we're not doing anything wrong

  -- Code exchange can only happen after the grant was fulfilled
  CONSTRAINT "oauth2_authorization_grants_exchanged_after_fullfill"
  CHECK (("exchanged_at" IS NULL)
      OR ("exchanged_at" IS NOT NULL   AND
          "fulfilled_at" IS NOT NULL   AND
          "exchanged_at" >= "fulfilled_at")),

  -- A grant can be either fulfilled or cancelled, but not both
  CONSTRAINT "oauth2_authorization_grants_fulfilled_xor_cancelled"
  CHECK ("fulfilled_at" IS NULL OR "cancelled_at" IS NULL),

  -- If it was fulfilled there is an oauth2_session_id attached to it
  CONSTRAINT "oauth2_authorization_grants_fulfilled_and_session"
  CHECK (("fulfilled_at" IS NULL     AND "oauth2_session_id" IS NULL)
      OR ("fulfilled_at" IS NOT NULL AND "oauth2_session_id" IS NOT NULL)),

  -- We should have a code if and only if the "code" response_type was asked
  CONSTRAINT "oauth2_authorization_grants_code"
  CHECK (("response_type_code" IS TRUE  AND "code" IS NOT NULL)
      OR ("response_type_code" IS FALSE AND "code" IS NULL)),

  -- If we have a challenge, we also have a challenge method and a code
  CONSTRAINT "oauth2_authorization_grants_code_challenge"
  CHECK (("code_challenge" IS NULL     AND "code_challenge_method" IS NULL)
      OR ("code_challenge" IS NOT NULL AND "code_challenge_method" IS NOT NULL AND "response_type_code" IS TRUE))
);
