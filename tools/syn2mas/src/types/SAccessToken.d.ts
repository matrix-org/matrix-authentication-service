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

import { SRefreshToken } from "./SRefreshToken";

import { Id, SynapseUserId } from "./index";

/*
CREATE TABLE access_tokens (
    id bigint NOT NULL,
    user_id text NOT NULL,
    device_id text,
    token text NOT NULL,
    valid_until_ms bigint,
    puppets_user_id text,
    last_validated bigint,
    refresh_token_id bigint,
    used boolean
);
*/
export interface SAccessToken {
  id: Id<SAccessToken>;
  user_id: SynapseUserId;
  device_id: string;
  token: string;
  valid_until_ms?: number;
  puppets_user_id?: SynapseUserId;
  last_validated?: number;
  refresh_token_id?: Id<SRefreshToken>;
  used: boolean;
}
