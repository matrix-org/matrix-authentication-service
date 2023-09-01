// Copyright 2022, 2023 The Matrix.org Foundation C.I.C.
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

import { useAtom, useAtomValue } from "jotai";
import { lazy, useEffect } from "react";

import LoadingSpinner from "../components/LoadingSpinner";

import { getRouteActionRedirection } from "./actions";
import { locationAtom, routeAtom } from "./atoms";
import type { Route } from "./routes";

/**
 * Check for actions in URL query params requiring a redirect
 * Get route from path
 * @returns Route
 */
const useRouteWithRedirect = (): [Route, boolean] => {
  const location = useAtomValue(locationAtom);
  const redirect = getRouteActionRedirection(location);

  const [route, setRoute] = useAtom(routeAtom);

  useEffect(() => {
    if (redirect) {
      setRoute(redirect.route, redirect.searchParams);
    }
  }, [redirect, setRoute]);

  const redirecting = !!redirect;
  return [route, redirecting];
};

const SessionsOverview = lazy(() => import("../pages/SessionsOverview"));
const SessionDetail = lazy(() => import("../pages/SessionDetail"));
const Profile = lazy(() => import("../pages/Profile"));
const OAuth2Client = lazy(() => import("../pages/OAuth2Client"));
const BrowserSession = lazy(() => import("../pages/BrowserSession"));
const BrowserSessionList = lazy(() => import("../pages/BrowserSessionList"));
const CompatSessionList = lazy(() => import("../pages/CompatSessionList"));
const OAuth2SessionList = lazy(() => import("../pages/OAuth2SessionList"));
const VerifyEmail = lazy(() => import("../pages/VerifyEmail"));

const Router: React.FC = () => {
  const [route, redirecting] = useRouteWithRedirect();

  if (redirecting) {
    return <LoadingSpinner />;
  }

  switch (route.type) {
    case "profile":
      return <Profile />;
    case "sessions-overview":
      return <SessionsOverview />;
    case "session":
      return <SessionDetail deviceId={route.id} />;
    case "oauth2-session-list":
      return <OAuth2SessionList />;
    case "browser-session-list":
      return <BrowserSessionList />;
    case "compat-session-list":
      return <CompatSessionList />;
    case "client":
      return <OAuth2Client id={route.id} />;
    case "browser-session":
      return <BrowserSession id={route.id} />;
    case "verify-email":
      return <VerifyEmail id={route.id} />;
    case "unknown":
      return <>Unknown route {JSON.stringify(route.segments)}</>;
  }
};

export default Router;
