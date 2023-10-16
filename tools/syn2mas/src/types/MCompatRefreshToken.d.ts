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

import { MCompatAccessToken } from "./MCompatAccessToken";
import { MCompatSession } from "./MCompatSession";

import { UUID } from "./index";

/*
+-------------------------+--------------------------+-----------+
| Column                  | Type                     | Modifiers |
|-------------------------+--------------------------+-----------|
| compat_refresh_token_id | uuid                     |  not null |
| compat_session_id       | uuid                     |  not null |
| compat_access_token_id  | uuid                     |  not null |
| refresh_token           | text                     |  not null |
| created_at              | timestamp with time zone |  not null |
| consumed_at             | timestamp with time zone |           |
+-------------------------+--------------------------+-----------+
Indexes:
    "compat_refresh_tokens_pkey" PRIMARY KEY, btree (compat_refresh_token_id)
    "compat_refresh_tokens_refresh_token_unique" UNIQUE CONSTRAINT, btree (refresh_token)
Foreign-key constraints:
    "compat_refresh_tokens_compat_access_token_id_fkey" FOREIGN KEY (compat_access_token_id) REFERENCES compat_access_tokens(compat_access_token_id)
    "compat_refresh_tokens_compat_session_id_fkey" FOREIGN KEY (compat_session_id) REFERENCES compat_sessions(compat_session_id)
*/
export interface MCompatRefreshToken {
  compat_refresh_token_id: UUID<MCompatRefreshToken>;
  compat_session_id: UUID<MCompatSession>;
  compat_access_token_id: UUID<MCompatAccessToken>;
  refresh_token: string;
  created_at: Date;
  consumed_at?: Date;
}
