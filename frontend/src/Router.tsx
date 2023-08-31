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

import { atom, useAtomValue, useSetAtom } from "jotai";
import { atomWithLocation } from "jotai-location";
import { lazy, Suspense, useTransition } from "react";

import styles from "./Router.module.css";
import Layout from "./components/Layout";
import LoadingSpinner from "./components/LoadingSpinner";

type Location = {
  pathname?: string;
  searchParams?: URLSearchParams;
};

type ProfileRoute = { type: "profile" };
type SessionOverviewRoute = { type: "sessions-overview" };
type SessionDetailRoute = { type: "session"; id: string };
type OAuth2ClientRoute = { type: "client"; id: string };
type OAuth2SessionList = { type: "oauth2-session-list" };
type BrowserSessionRoute = { type: "browser-session"; id: string };
type BrowserSessionListRoute = { type: "browser-session-list" };
type CompatSessionListRoute = { type: "compat-session-list" };
type VerifyEmailRoute = { type: "verify-email"; id: string };
type UnknownRoute = { type: "unknown"; segments: string[] };

export type Route =
  | SessionOverviewRoute
  | SessionDetailRoute
  | ProfileRoute
  | OAuth2ClientRoute
  | OAuth2SessionList
  | BrowserSessionRoute
  | BrowserSessionListRoute
  | CompatSessionListRoute
  | VerifyEmailRoute
  | UnknownRoute;

const routeToSegments = (route: Route): string[] => {
  switch (route.type) {
    case "profile":
      return [];
    case "sessions-overview":
      return ["sessions-overview"];
    case "session":
      return ["session", route.id];
    case "verify-email":
      return ["emails", route.id, "verify"];
    case "client":
      return ["clients", route.id];
    case "browser-session-list":
      return ["browser-sessions"];
    case "browser-session":
      return ["browser-sessions", route.id];
    case "oauth2-session-list":
      return ["oauth2-sessions"];
    case "compat-session-list":
      return ["compat-sessions"];
    case "unknown":
      return route.segments;
  }
};

const P = Symbol();
type PatternItem = string | typeof P;

// Returns true if the segments match the pattern, where P is a parameter
const segmentMatches = (
  segments: string[],
  ...pattern: PatternItem[]
): boolean => {
  // Quick check to see if the lengths match
  if (segments.length !== pattern.length) return false;

  // Check each segment
  for (let i = 0; i < segments.length; i++) {
    // If the pattern is P, then it's a parameter and we can skip it
    if (pattern[i] === P) continue;
    // Otherwise, check that the segment matches the pattern
    if (segments[i] !== pattern[i]) return false;
  }

  return true;
};

export const segmentsToRoute = (segments: string[]): Route => {
  const matches = (...pattern: PatternItem[]): boolean =>
    segmentMatches(segments, ...pattern);

  // Special case for the home page
  if (segments.length === 0 || (segments.length === 1 && segments[0] === "")) {
    return { type: "profile" };
  }

  if (matches("sessions-overview")) {
    return { type: "sessions-overview" };
  }

  if (matches("browser-sessions")) {
    return { type: "browser-session-list" };
  }

  if (matches("oauth2-sessions")) {
    return { type: "oauth2-session-list" };
  }

  if (matches("compat-sessions")) {
    return { type: "compat-session-list" };
  }

  if (matches("emails", P, "verify")) {
    return { type: "verify-email", id: segments[1] };
  }

  if (matches("clients", P)) {
    return { type: "client", id: segments[1] };
  }

  if (matches("browser-sessions", P)) {
    return { type: "browser-session", id: segments[1] };
  }

  if (matches("session", P)) {
    return { type: "session", id: segments[1] };
  }

  return { type: "unknown", segments };
};

const routeToPath = (route: Route): string =>
  routeToSegments(route)
    .map((part) => encodeURIComponent(part))
    .join("/");

export const appConfigAtom = atom<AppConfig>(
  typeof window !== "undefined" ? window.APP_CONFIG : { root: "/" },
);

const pathToRoute = (path: string): Route => {
  const segments = path.split("/").map(decodeURIComponent);
  return segmentsToRoute(segments);
};

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
  (get, set, value: Route) => {
    const appConfig = get(appConfigAtom);
    set(locationAtom, {
      pathname: appConfig.root + routeToPath(value),
    });
  },
);

const SessionsOverview = lazy(() => import("./pages/SessionsOverview"));
const SessionDetail = lazy(() => import("./pages/SessionDetail"));
const Profile = lazy(() => import("./pages/Profile"));
const OAuth2Client = lazy(() => import("./pages/OAuth2Client"));
const BrowserSession = lazy(() => import("./pages/BrowserSession"));
const BrowserSessionList = lazy(() => import("./pages/BrowserSessionList"));
const CompatSessionList = lazy(() => import("./pages/CompatSessionList"));
const OAuth2SessionList = lazy(() => import("./pages/OAuth2SessionList"));
const VerifyEmail = lazy(() => import("./pages/VerifyEmail"));

const InnerRouter: React.FC = () => {
  const route = useAtomValue(routeAtom);

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

const Router: React.FC = () => (
  <Layout>
    <Suspense fallback={<LoadingSpinner />}>
      <InnerRouter />
    </Suspense>
  </Layout>
);

// Filter out clicks with modifiers or that have been prevented
const shouldHandleClick = (e: React.MouseEvent): boolean =>
  !e.defaultPrevented &&
  e.button === 0 &&
  !(e.metaKey || e.altKey || e.ctrlKey || e.shiftKey);

export const Link: React.FC<
  {
    route: Route;
    // adds button-like styling to link element
    kind?: "button";
  } & React.HTMLProps<HTMLAnchorElement>
> = ({ route, children, kind, className, ...props }) => {
  const config = useAtomValue(appConfigAtom);
  const path = routeToPath(route);
  const fullUrl = config.root + path;
  const setRoute = useSetAtom(routeAtom);

  // TODO: we should probably have more user control over this
  const [isPending, startTransition] = useTransition();

  const classNames = [
    kind === "button" ? styles.linkButton : "",
    className,
  ].join("");

  return (
    <a
      href={fullUrl}
      onClick={(e: React.MouseEvent): void => {
        // Only handle left clicks without modifiers
        if (!shouldHandleClick(e)) {
          return;
        }

        e.preventDefault();
        startTransition(() => {
          setRoute(route);
        });
      }}
      className={classNames}
      {...props}
    >
      {isPending ? "Loading..." : children}
    </a>
  );
};

export default Router;
