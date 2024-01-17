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

import { MUser } from "./MUser";

import { UUID } from "./index";

/*
+-------------------+--------------------------+-----------+
| Column            | Type                     | Modifiers |
|-------------------+--------------------------+-----------|
| compat_session_id | uuid                     |  not null |
| user_id           | uuid                     |  not null |
| device_id         | text                     |  not null |
| created_at        | timestamp with time zone |  not null |
| finished_at       | timestamp with time zone |           |
| is_synapse_admin  | boolean                  | not null  |
+-------------------+--------------------------+-----------+
Indexes:
    "compat_sessions_pkey" PRIMARY KEY, btree (compat_session_id)
    "compat_sessions_device_id_unique" UNIQUE CONSTRAINT, btree (device_id)
Foreign-key constraints:
    "compat_sessions_user_id_fkey" FOREIGN KEY (user_id) REFERENCES users(user_id)
Referenced by:
    TABLE "compat_sso_logins" CONSTRAINT "compat_sso_logins_compat_session_id_fkey" FOREIGN KEY (compat_session_id) REFERENCES compat_sessions(compat_session_id) ON DELETE SET NULL
    TABLE "compat_access_tokens" CONSTRAINT "compat_access_tokens_compat_session_id_fkey" FOREIGN KEY (compat_session_id) REFERENCES compat_sessions(compat_session_id)
    TABLE "compat_refresh_tokens" CONSTRAINT "compat_refresh_tokens_compat_session_id_fkey" FOREIGN KEY (compat_session_id) REFERENCES compat_sessions(compat_session_id)
*/

export interface MCompatSession {
  compat_session_id: UUID<MCompatSession>;
  user_id: UUID<MUser>;
  device_id: string;
  created_at: Date;
  finished_at?: Date;
  is_synapse_admin: boolean;
}
