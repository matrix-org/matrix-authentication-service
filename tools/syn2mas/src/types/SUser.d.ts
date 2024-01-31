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

import { SynapseUserId, UnixTimestamp } from "./index";

export interface SUser {
  name: SynapseUserId; // '@test2:localhost:8008'
  password_hash?: string;
  admin: number;
  is_guest: number;
  deactivated: number;
  creation_ts: UnixTimestamp;
  appservice_id?: string;
}
