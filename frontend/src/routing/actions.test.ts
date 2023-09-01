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

import { it, expect, describe } from "vitest";

import { getRouteActionRedirection } from "./actions";

describe("getRouteActionRedirection()", () => {
  it("no redirect when location has no searchParams", () => {
    expect(
      getRouteActionRedirection({ pathname: "/account/" }),
    ).toBeUndefined();
  });

  it("no redirect when location has empty searchParams", () => {
    expect(
      getRouteActionRedirection({
        pathname: "/account/",
        searchParams: new URLSearchParams(),
      }),
    ).toBeUndefined();
  });

  it("no redirect when location has an unknown action in search params", () => {
    expect(
      getRouteActionRedirection({
        pathname: "/account/",
        searchParams: new URLSearchParams("?action=test"),
      }),
    ).toBeUndefined();
  });

  it("redirects to session detail when location has a action=session_end", () => {
    const searchParams = new URLSearchParams();
    searchParams.set("action", "session_end");
    searchParams.set("device_id", "test-device-id");
    searchParams.set("something_else", "should-remain");
    expect(
      getRouteActionRedirection({ pathname: "/account/", searchParams }),
    ).toEqual({
      route: {
        type: "session",
        id: "test-device-id",
      },
      searchParams: new URLSearchParams("?something_else=should-remain"),
    });
  });

  it("redirects to session detail when location has a action=session_view", () => {
    const searchParams = new URLSearchParams();
    searchParams.set("action", "session_view");
    searchParams.set("device_id", "test-device-id");
    expect(
      getRouteActionRedirection({ pathname: "/account/", searchParams }),
    ).toEqual({
      route: {
        type: "session",
        id: "test-device-id",
      },
    });
  });

  it("redirects to sessions overview when location has a action=sessions_list", () => {
    const searchParams = new URLSearchParams();
    searchParams.set("action", "sessions_list");
    expect(
      getRouteActionRedirection({ pathname: "/account/", searchParams }),
    ).toEqual({
      route: {
        type: "sessions-overview",
      },
    });
  });

  it("redirects to profile when location has a action=profile", () => {
    const searchParams = new URLSearchParams();
    searchParams.set("action", "profile");
    expect(
      getRouteActionRedirection({ pathname: "/account/", searchParams }),
    ).toEqual({
      route: {
        type: "profile",
      },
    });
  });
});
