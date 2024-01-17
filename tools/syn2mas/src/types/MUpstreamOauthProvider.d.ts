// Copyright 2023 The Matrix.org Foundation C.I.C.
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

import { UUID } from "./index";

/*
+----------------------------+--------------------------+-----------+
| Column                     | Type                     | Modifiers |
|----------------------------+--------------------------+-----------|
| upstream_oauth_provider_id | uuid                     |  not null |
| issuer                     | text                     |  not null |
| scope                      | text                     |  not null |
| client_id                  | text                     |  not null |
| encrypted_client_secret    | text                     |           |
| token_endpoint_signing_alg | text                     |           |
| token_endpoint_auth_method | text                     |  not null |
| created_at                 | timestamp with time zone |  not null |
+----------------------------+--------------------------+-----------+
Indexes:
    "upstream_oauth_providers_pkey" PRIMARY KEY, btree (upstream_oauth_provider_id)
Referenced by:
    TABLE "upstream_oauth_links" CONSTRAINT "upstream_oauth_links_provider_fkey" FOREIGN KEY (upstream_oauth_provider_id) REFERENCES upstream_oauth_providers(upstream_oauth_provider_id)
    TABLE "upstream_oauth_authorization_sessions" CONSTRAINT "upstream_oauth_authorization_sessions_provider_fkey" FOREIGN KEY (upstream_oauth_provider_id) REFERENCES upstream_oauth_providers(upstream_oauth_provider_id)
*/

export interface MUpstreamOauthProvider {
  upstream_oauth_provider_id: UUID<MUpstreamOauthProvider>;
  issuer: string;
  scope: string;
  client_id: string;
  encrypted_client_secret?: string;
  token_endpoint_signing_alg?: string;
  token_endpoint_auth_method: string;
  created_at: Date;
}
