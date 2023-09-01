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

import { Location, Route } from "./routes";

// As defined by MSC2965
// https://github.com/sandhose/matrix-doc/blob/msc/sandhose/oidc-discovery/proposals/2965-oidc-discovery.md#account-management-url-parameters
enum RouteAction {
  EndSession = "session_end",
  ViewSession = "session_view",
  ListSessions = "sessions_list",
  Profile = "profile",
}

export const getRouteActionRedirection = (
  location: Location,
): null | {
  route: Route;
  searchParams?: URLSearchParams;
} => {
  // Clone the search params so we can modify them
  const searchParams = new URLSearchParams(location.searchParams?.toString());
  const action = searchParams?.get("action");
  const deviceId = searchParams?.get("device_id");
  searchParams?.delete("action");
  searchParams?.delete("device_id");

  let route: Route;
  switch (action) {
    case RouteAction.EndSession:
      route = {
        type: "session",
        id: deviceId || "",
      };
      break;

    case RouteAction.ViewSession:
      route = {
        type: "session",
        id: deviceId || "",
      };
      break;

    case RouteAction.ListSessions:
      route = {
        type: "sessions-overview",
      };
      break;

    case RouteAction.Profile:
      route = {
        type: "profile",
      };
      break;

    default:
      return null;
  }

  return {
    route,
    searchParams: searchParams.toString() ? searchParams : undefined,
  };
};
