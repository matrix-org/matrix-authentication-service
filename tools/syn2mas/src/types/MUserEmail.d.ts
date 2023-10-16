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
+---------------+--------------------------+-----------+
| Column        | Type                     | Modifiers |
|---------------+--------------------------+-----------|
| user_email_id | uuid                     |  not null |
| user_id       | uuid                     |  not null |
| email         | text                     |  not null |
| created_at    | timestamp with time zone |  not null |
| confirmed_at  | timestamp with time zone |           |
+---------------+--------------------------+-----------+
*/

export interface MUserEmail {
  user_email_id: UUID<MUserEmail>;
  user_id: UUID<MUser>;
  email: string;
  created_at: Date;
  confirmed_at?: Date;
}
