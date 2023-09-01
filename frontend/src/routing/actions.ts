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

enum RouteAction {
  EndSession = "session_end",
}

export const getRouteActionRedirection = (
  location: Location,
):
  | undefined
  | {
      route: Route;
      searchParams?: URLSearchParams;
    } => {
  const action = location.searchParams?.get("action");

  if (!action) {
    return;
  }

  if (action === RouteAction.EndSession) {
    const searchParams = new URLSearchParams(location.searchParams?.toString());
    searchParams.delete("action");
    searchParams.delete("device_id");
    return {
      route: {
        type: "session",
        id: location.searchParams?.get("device_id") || "",
      },
      searchParams,
    };
  }
};
