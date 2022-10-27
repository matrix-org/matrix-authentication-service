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

-----------
-- Users --
-----------

CREATE TABLE "users" (
  "user_id" UUID NOT NULL
    CONSTRAINT "users_pkey"
    PRIMARY KEY,

  "username" TEXT NOT NULL
    CONSTRAINT "users_username_unique"
    UNIQUE,

  "created_at" TIMESTAMP WITH TIME ZONE NOT NULL
);

CREATE TABLE "user_passwords" (
  "user_password_id" UUID NOT NULL
    CONSTRAINT "user_passwords_pkey"
    PRIMARY KEY,

  "user_id" UUID NOT NULL
    CONSTRAINT "user_passwords_user_id_fkey"
    REFERENCES "users" ("user_id"),

  "hashed_password" TEXT NOT NULL,
  "created_at" TIMESTAMP WITH TIME ZONE NOT NULL
);

CREATE TABLE "user_emails" (
  "user_email_id" UUID NOT NULL
    CONSTRAINT "user_emails_pkey"
    PRIMARY KEY,

  "user_id" UUID NOT NULL
    CONSTRAINT "user_emails_user_id_fkey"
    REFERENCES "users" ("user_id")
    ON DELETE CASCADE,

  "email" TEXT NOT NULL,
  "created_at" TIMESTAMP WITH TIME ZONE NOT NULL,
  "confirmed_at" TIMESTAMP WITH TIME ZONE
);

ALTER TABLE "users"
  ADD COLUMN "primary_user_email_id" UUID
    CONSTRAINT "users_primary_user_email_id_fkey"
    REFERENCES "user_emails" ("user_email_id")
    ON DELETE SET NULL;

CREATE TABLE "user_email_confirmation_codes" (
  "user_email_confirmation_code_id" UUID NOT NULL
    CONSTRAINT "user_email_confirmation_codes_pkey"
    PRIMARY KEY,

  "user_email_id" UUID NOT NULL
    CONSTRAINT "user_email_confirmation_codes_user_email_id_fkey"
    REFERENCES "user_emails" ("user_email_id"),

  "code" TEXT NOT NULL
    CONSTRAINT "user_email_confirmation_codes_code_unique"
    UNIQUE,

  "created_at" TIMESTAMP WITH TIME ZONE NOT NULL,
  "expires_at" TIMESTAMP WITH TIME ZONE NOT NULL,
  "consumed_at" TIMESTAMP WITH TIME ZONE
);

CREATE TABLE "user_sessions" (
  "user_session_id" UUID NOT NULL
    CONSTRAINT "user_sessions_pkey"
    PRIMARY KEY,

  "user_id" UUID NOT NULL
    CONSTRAINT "user_sessions_user_id_fkey"
    REFERENCES "users" ("user_id"),

  "created_at" TIMESTAMP WITH TIME ZONE NOT NULL,
  "finished_at" TIMESTAMP WITH TIME ZONE
);

CREATE TABLE "user_session_authentications" (
  "user_session_authentication_id" UUID NOT NULL
    CONSTRAINT "user_session_authentications_pkey"
    PRIMARY KEY,

  "user_session_id" UUID NOT NULL
    CONSTRAINT "user_session_authentications_user_session_id_fkey"
    REFERENCES "user_sessions" ("user_session_id"),

  "created_at" TIMESTAMP WITH TIME ZONE NOT NULL
);

---------------------
-- Compat sessions --
---------------------

CREATE TABLE "compat_sessions" (
  "compat_session_id" UUID NOT NULL
    CONSTRAINT "compat_sessions_pkey"
    PRIMARY KEY,

  "user_id" UUID NOT NULL
    CONSTRAINT "compat_sessions_user_id_fkey"
    REFERENCES "users" ("user_id"),

  "device_id" TEXT NOT NULL
    CONSTRAINT "compat_sessions_device_id_unique"
    UNIQUE,

  "created_at" TIMESTAMP WITH TIME ZONE NOT NULL,
  "finished_at" TIMESTAMP WITH TIME ZONE
);

CREATE TABLE "compat_sso_logins" (
  "compat_sso_login_id" UUID NOT NULL
    CONSTRAINT "compat_sso_logins_pkey"
    PRIMARY KEY,

  "redirect_uri" TEXT NOT NULL,

  "login_token" TEXT NOT NULL
    CONSTRAINT "compat_sessions_login_token_unique"
    UNIQUE,

  "compat_session_id" UUID
    CONSTRAINT "compat_sso_logins_compat_session_id_fkey"
    REFERENCES "compat_sessions" ("compat_session_id")
    ON DELETE SET NULL,

  "created_at" TIMESTAMP WITH TIME ZONE NOT NULL,
  "fulfilled_at" TIMESTAMP WITH TIME ZONE,
  "exchanged_at" TIMESTAMP WITH TIME ZONE
);

CREATE TABLE "compat_access_tokens" (
  "compat_access_token_id" UUID NOT NULL
    CONSTRAINT "compat_access_tokens_pkey"
    PRIMARY KEY,

  "compat_session_id" UUID NOT NULL
    CONSTRAINT "compat_access_tokens_compat_session_id_fkey"
    REFERENCES "compat_sessions" ("compat_session_id"),

  "access_token" TEXT NOT NULL
    CONSTRAINT "compat_access_tokens_access_token_unique"
    UNIQUE,

  "created_at" TIMESTAMP WITH TIME ZONE NOT NULL,
  "expires_at" TIMESTAMP WITH TIME ZONE
);

CREATE TABLE "compat_refresh_tokens" (
  "compat_refresh_token_id" UUID NOT NULL
    CONSTRAINT "compat_refresh_tokens_pkey"
    PRIMARY KEY,

  "compat_session_id" UUID NOT NULL
    CONSTRAINT "compat_refresh_tokens_compat_session_id_fkey"
    REFERENCES "compat_sessions" ("compat_session_id"),

  "compat_access_token_id" UUID NOT NULL
    CONSTRAINT "compat_refresh_tokens_compat_access_token_id_fkey"
    REFERENCES "compat_access_tokens" ("compat_access_token_id"),

  "refresh_token" TEXT NOT NULL
    CONSTRAINT "compat_refresh_tokens_refresh_token_unique"
    UNIQUE,

  "created_at" TIMESTAMP WITH TIME ZONE NOT NULL,
  "consumed_at" TIMESTAMP WITH TIME ZONE
);

----------------
-- OAuth 2.0 ---
----------------

CREATE TABLE "oauth2_clients" (
  "oauth2_client_id" UUID NOT NULL
    CONSTRAINT "oauth2_clients_pkey"
    PRIMARY KEY,

  "encrypted_client_secret" TEXT,

  "grant_type_authorization_code" BOOLEAN NOT NULL,
  "grant_type_refresh_token" BOOLEAN NOT NULL,

  "client_name" TEXT,
  "logo_uri" TEXT,
  "client_uri" TEXT,
  "policy_uri" TEXT,
  "tos_uri" TEXT,

  "jwks_uri" TEXT,
  "jwks" JSONB,

  "id_token_signed_response_alg" TEXT,
  "token_endpoint_auth_method" TEXT,
  "token_endpoint_auth_signing_alg" TEXT,
  "initiate_login_uri" TEXT,
  "userinfo_signed_response_alg" TEXT,

  "created_at" TIMESTAMP WITH TIME ZONE NULL
);

CREATE TABLE "oauth2_client_redirect_uris" (
  "oauth2_client_redirect_uri_id" UUID NOT NULL
    CONSTRAINT "oauth2_client_redirect_uris_pkey"
    PRIMARY KEY,

  "oauth2_client_id" UUID NOT NULL
    CONSTRAINT "tbl_oauth2_client_id_fkey"
    REFERENCES "oauth2_clients" ("oauth2_client_id"),

  "redirect_uri" TEXT NOT NULL
);

CREATE TABLE "oauth2_sessions" (
  "oauth2_session_id" UUID NOT NULL
    CONSTRAINT "oauth2_sessions_pkey"
    PRIMARY KEY,

  "user_session_id" UUID NOT NULL
    CONSTRAINT "oauth2_sessions_user_session_id_fkey"
    REFERENCES "user_sessions" ("user_session_id"),

  "oauth2_client_id" UUID NOT NULL
    CONSTRAINT "oauth2_sessions_oauth2_client_id_fkey"
    REFERENCES "oauth2_clients" ("oauth2_client_id"),

  "scope" TEXT NOT NULL,

  "created_at" TIMESTAMP WITH TIME ZONE NOT NULL,
  "finished_at" TIMESTAMP WITH TIME ZONE
);

CREATE TABLE "oauth2_consents" (
  "oauth2_consent_id" UUID NOT NULL
    CONSTRAINT "oauth2_consents_pkey"
    PRIMARY KEY,

  "oauth2_client_id" UUID NOT NULL
    CONSTRAINT "oauth2_consents_oauth2_client_id_fkey"
    REFERENCES "oauth2_clients" ("oauth2_client_id"),

  "user_id" UUID NOT NULL
    CONSTRAINT "oauth2_consents_user_id_fkey"
    REFERENCES "users" ("user_id"),

  "scope_token" TEXT NOT NULL,

  "created_at" TIMESTAMP WITH TIME ZONE NOT NULL,
  "refreshed_at" TIMESTAMP WITH TIME ZONE,

  CONSTRAINT "oauth2_consents_unique"
    UNIQUE ("oauth2_client_id", "user_id", "scope_token")
);

CREATE INDEX "oauth2_consents_oauth2_client_id_user_id"
  ON "oauth2_consents" ("oauth2_client_id", "user_id");

CREATE TABLE "oauth2_access_tokens" (
  "oauth2_access_token_id" UUID NOT NULL
    CONSTRAINT "oauth2_access_tokens_pkey"
    PRIMARY KEY,

  "oauth2_session_id" UUID NOT NULL
    CONSTRAINT "oauth2_access_tokens_oauth2_session_id_fkey"
    REFERENCES "oauth2_sessions" ("oauth2_session_id"),

  "access_token" TEXT NOT NULL
    CONSTRAINT "oauth2_access_tokens_unique"
    UNIQUE,

  "created_at" TIMESTAMP WITH TIME ZONE NOT NULL,
  "expires_at" TIMESTAMP WITH TIME ZONE NOT NULL,
  "revoked_at" TIMESTAMP WITH TIME ZONE
);

CREATE TABLE "oauth2_refresh_tokens" (
  "oauth2_refresh_token_id" UUID NOT NULL
    CONSTRAINT "oauth2_refresh_tokens_pkey"
    PRIMARY KEY,

  "oauth2_session_id" UUID NOT NULL
    CONSTRAINT "oauth2_access_tokens_oauth2_session_id_fkey"
    REFERENCES "oauth2_sessions" ("oauth2_session_id"),

  "oauth2_access_token_id" UUID
    CONSTRAINT "oauth2_refresh_tokens_oauth2_access_token_id_fkey"
    REFERENCES "oauth2_access_tokens" ("oauth2_access_token_id")
    ON DELETE SET NULL,

  "refresh_token" TEXT NOT NULL
    CONSTRAINT "oauth2_refresh_tokens_unique"
    UNIQUE,

  "created_at" TIMESTAMP WITH TIME ZONE NOT NULL,
  "consumed_at" TIMESTAMP WITH TIME ZONE,
  "revoked_at" TIMESTAMP WITH TIME ZONE
);

CREATE TABLE "oauth2_authorization_grants" (
  "oauth2_authorization_grant_id" UUID NOT NULL
    CONSTRAINT "oauth2_authorization_grants_pkey"
    PRIMARY KEY,

  "oauth2_client_id" UUID NOT NULL
    CONSTRAINT "tbl_oauth2_client_fkey"
    REFERENCES "oauth2_clients" ("oauth2_client_id"),

  "oauth2_session_id" UUID
    CONSTRAINT "tbl_oauth2_session_fkey"
    REFERENCES "oauth2_sessions" ("oauth2_session_id"),

  "authorization_code" TEXT
    CONSTRAINT "oauth2_authorization_grants_authorization_code_unique"
    UNIQUE,

  "redirect_uri" TEXT NOT NULL,

  "scope" TEXT NOT NULL,
  "state" TEXT,
  "nonce" TEXT,
  "max_age" INTEGER,
  "response_mode" TEXT NOT NULL,
  "code_challenge_method" TEXT,
  "code_challenge" TEXT,
  "response_type_code" BOOLEAN NOT NULL,
  "response_type_id_token" BOOLEAN NOT NULL,
  "requires_consent" BOOLEAN NOT NULL,

  "created_at" TIMESTAMP WITH TIME ZONE NOT NULL,
  "fulfilled_at" TIMESTAMP WITH TIME ZONE,
  "cancelled_at" TIMESTAMP WITH TIME ZONE,
  "exchanged_at" TIMESTAMP WITH TIME ZONE
);
