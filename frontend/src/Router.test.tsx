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

import { describe, it, expect } from "vitest";

import { segmentsToRoute } from "./Router";

describe("Router", () => {
  describe("segmentsToRoute", () => {
    it("returns profile for route with no segments", () => {
      const segments: string[] = [];
      expect(segmentsToRoute(segments)).toEqual({ type: "profile" });
    });

    it("returns profile for route with and empty string segment", () => {
      const segments: string[] = [""];
      expect(segmentsToRoute(segments)).toEqual({ type: "profile" });
    });

    it("returns browser session list for browser-sessions", () => {
      const segments: string[] = ["browser-sessions"];
      expect(segmentsToRoute(segments)).toEqual({
        type: "browser-session-list",
      });
    });

    it("returns compat session list for compat-sessions", () => {
      const segments: string[] = ["compat-sessions"];
      expect(segmentsToRoute(segments)).toEqual({
        type: "compat-session-list",
      });
    });

    it("returns oauth session list for oauth2-sessions", () => {
      const segments: string[] = ["oauth2-sessions"];
      expect(segmentsToRoute(segments)).toEqual({
        type: "oauth2-session-list",
      });
    });

    it("returns client detail route correctly", () => {
      const segments: string[] = ["clients", "client-id"];
      expect(segmentsToRoute(segments)).toEqual({
        type: "client",
        id: "client-id",
      });
    });

    it("returns browser session detail route correctly", () => {
      const segments: string[] = ["browser-sessions", "session-id"];
      expect(segmentsToRoute(segments)).toEqual({
        type: "browser-session",
        id: "session-id",
      });
    });

    it("returns session detail route correctly", () => {
      const segments: string[] = ["session", "device-id"];
      expect(segmentsToRoute(segments)).toEqual({
        type: "session",
        id: "device-id",
      });
    });

    it("returns unknown for other segments", () => {
      const segments: string[] = ["just", "testing"];
      expect(segmentsToRoute(segments)).toEqual({ type: "unknown", segments });
    });
  });
});
