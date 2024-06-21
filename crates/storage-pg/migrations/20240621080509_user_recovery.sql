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

-- Stores user recovery sessions for when the user lost their credentials.
CREATE TABLE "user_recovery_sessions" (
  "user_recovery_session_id" UUID NOT NULL
    CONSTRAINT "user_recovery_sessions_pkey"
    PRIMARY KEY,

  -- The email address for which the recovery session was requested
  "email" TEXT NOT NULL,

  -- The user agent of the client that requested the recovery session
  "user_agent" TEXT NOT NULL,

  -- The IP address of the client that requested the recovery session
  "ip_address" INET,

  -- The language of the client that requested the recovery session
  "locale" TEXT NOT NULL,

  -- When the recovery session was created
  "created_at" TIMESTAMP WITH TIME ZONE NOT NULL,

  -- When the recovery session was consumed
  "consumed_at" TIMESTAMP WITH TIME ZONE
);

-- Stores the recovery tickets for a user recovery session.
CREATE TABLE "user_recovery_tickets" (
  "user_recovery_ticket_id" UUID NOT NULL
    CONSTRAINT "user_recovery_tickets_pkey"
    PRIMARY KEY,

  -- The recovery session this ticket belongs to
  "user_recovery_session_id" UUID NOT NULL
    REFERENCES "user_recovery_sessions" ("user_recovery_session_id")
    ON DELETE CASCADE,

  -- The user_email for which the recovery ticket was generated
  "user_email_id" UUID NOT NULL
    REFERENCES "user_emails" ("user_email_id")
    ON DELETE CASCADE,

  -- The recovery ticket
  "ticket" TEXT NOT NULL,

  -- When the recovery ticket was created
  "created_at" TIMESTAMP WITH TIME ZONE NOT NULL,

  -- When the recovery ticket expires
  "expires_at" TIMESTAMP WITH TIME ZONE NOT NULL
);
