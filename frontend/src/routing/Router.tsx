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
import { useEffect } from "react";
import { useTranslation } from "react-i18next";

import LoadingSpinner from "../components/LoadingSpinner";
import BrowserSession from "../pages/BrowserSession";
import BrowserSessionList from "../pages/BrowserSessionList";
import OAuth2Client from "../pages/OAuth2Client";
import Profile from "../pages/Profile";
import SessionDetail from "../pages/SessionDetail";
import SessionsOverview from "../pages/SessionsOverview";
import VerifyEmail from "../pages/VerifyEmail";

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

// A type-safe way to ensure we've handled all routes
const unknownRoute = (route: never): never => {
  throw new Error(`Invalid route: ${JSON.stringify(route)}`);
};

const Router: React.FC<{ userId: string }> = ({ userId }) => {
  const [route, redirecting] = useRouteWithRedirect();
  const { t } = useTranslation();

  if (redirecting) {
    return <LoadingSpinner />;
  }

  switch (route.type) {
    case "profile":
      return <Profile userId={userId} />;
    case "sessions-overview":
      return <SessionsOverview />;
    case "session":
      return <SessionDetail userId={userId} deviceId={route.id} />;
    case "browser-session-list":
      return <BrowserSessionList userId={userId} />;
    case "client":
      return <OAuth2Client id={route.id} />;
    case "browser-session":
      return <BrowserSession id={route.id} />;
    case "verify-email":
      return <VerifyEmail id={route.id} />;
    case "unknown":
      return (
        <>
          {t("frontend.unknown_route", {
            route: JSON.stringify(route.segments),
          })}
        </>
      );
    default:
      unknownRoute(route);
  }
};

export default Router;
