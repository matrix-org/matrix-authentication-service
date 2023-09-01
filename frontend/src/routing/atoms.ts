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

import { atom } from "jotai";
import { atomWithLocation } from "jotai-location";

import { Location, pathToRoute, Route, routeToPath } from "./routes";

export const appConfigAtom = atom<AppConfig>(
  typeof window !== "undefined" ? window.APP_CONFIG : { root: "/" },
);

const locationToRoute = (root: string, location: Location): Route => {
  if (!location.pathname || !location.pathname.startsWith(root)) {
    throw new Error(`Invalid location ${location.pathname}`);
  }

  const path = location.pathname.slice(root.length);
  return pathToRoute(path);
};

export const locationAtom = atomWithLocation();

export const routeAtom = atom(
  (get) => {
    const location = get(locationAtom);
    const config = get(appConfigAtom);
    return locationToRoute(config.root, location);
  },
  (get, set, value: Route, searchParams?: URLSearchParams) => {
    const appConfig = get(appConfigAtom);
    set(locationAtom, {
      pathname: appConfig.root + routeToPath(value),
      searchParams,
    });
  },
);
