/* Copyright 2023 The Matrix.org Foundation C.I.C.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

import { describe, it, expect } from "vitest";

import { getDeviceIdFromScope } from "./deviceIdFromScope";

describe("getDeviceIdFromScope()", () => {
  it("returns deviceid when device is part of scope", () => {
    const scope =
      "openid urn:matrix:org.matrix.msc2967.client:api:* urn:matrix:org.matrix.msc2967.client:device:abcd1234";
    expect(getDeviceIdFromScope(scope)).toEqual("abcd1234");
  });

  it("returns undefined when device not part of scope", () => {
    const scope = "openid some:other:scope ";
    expect(getDeviceIdFromScope(scope)).toBeUndefined();
  });
});
