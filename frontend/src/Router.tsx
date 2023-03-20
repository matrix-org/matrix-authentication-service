// Copyright 2022 The Matrix.org Foundation C.I.C.
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

import { lazy, Suspense, useTransition } from "react";
import { atomWithLocation } from "jotai-location";
import { atom, useAtomValue, useSetAtom } from "jotai";

import Layout from "./components/Layout";
import LoadingSpinner from "./components/LoadingSpinner";

type Location = {
  pathname?: string;
  searchParams?: URLSearchParams;
};

type HomeRoute = { type: "home" };
type DumbRoute = { type: "dumb" };
type OAuth2ClientRoute = { type: "client"; id: string };
type BrowserSessionRoute = { type: "session"; id: string };
type UnknownRoute = { type: "unknown"; segments: string[] };

export type Route =
  | HomeRoute
  | DumbRoute
  | OAuth2ClientRoute
  | BrowserSessionRoute
  | UnknownRoute;

const routeToSegments = (route: Route): string[] => {
  switch (route.type) {
    case "home":
      return [];
    case "dumb":
      return ["dumb"];
    case "client":
      return ["client", route.id];
    case "session":
      return ["session", route.id];
    case "unknown":
      return route.segments;
  }
};

const segmentsToRoute = (segments: string[]): Route => {
  if (segments.length === 0 || (segments.length === 1 && segments[0] === "")) {
    return { type: "home" };
  }

  if (segments.length === 1 && segments[0] === "dumb") {
    return { type: "dumb" };
  }

  if (segments.length === 2 && segments[0] === "client") {
    return { type: "client", id: segments[1] };
  }

  if (segments.length === 2 && segments[0] === "session") {
    return { type: "session", id: segments[1] };
  }

  return { type: "unknown", segments };
};

const routeToPath = (route: Route): string =>
  routeToSegments(route)
    .map((part) => encodeURIComponent(part))
    .join("/");

const pathToRoute = (path: string): Route => {
  const segments = path.split("/").map(decodeURIComponent);
  return segmentsToRoute(segments);
};

const locationToRoute = (location: Location): Route => {
  if (
    !location.pathname ||
    !location.pathname.startsWith(window.APP_CONFIG.root)
  ) {
    throw new Error("Invalid location");
  }

  const path = location.pathname.slice(window.APP_CONFIG.root.length);
  return pathToRoute(path);
};

const locationAtom = atomWithLocation();
export const routeAtom = atom(
  (get) => locationToRoute(get(locationAtom)),
  (_get, set, value: Route) => {
    set(locationAtom, {
      pathname: window.APP_CONFIG.root + routeToPath(value),
    });
  }
);

const Home = lazy(() => import("./pages/Home"));
const OAuth2Client = lazy(() => import("./pages/OAuth2Client"));
const BrowserSession = lazy(() => import("./pages/BrowserSession"));

const InnerRouter: React.FC = () => {
  const route = useAtomValue(routeAtom);

  switch (route.type) {
    case "home":
      return <Home />;
    case "client":
      return <OAuth2Client id={route.id} />;
    case "session":
      return <BrowserSession id={route.id} />;
    case "dumb":
      return <>Dumb route.</>;
    case "unknown":
      return <>Unknown route {JSON.stringify(route.segments)}</>;
  }
};

const Router = () => (
  <Layout>
    <Suspense fallback={<LoadingSpinner />}>
      <InnerRouter />
    </Suspense>
  </Layout>
);

export const Link: React.FC<
  {
    route: Route;
    children: React.ReactNode;
  } & React.HTMLProps<HTMLAnchorElement>
> = ({ route, children, ...props }) => {
  const path = routeToPath(route);
  const setRoute = useSetAtom(routeAtom);

  // TODO: we should probably have more user control over this
  const [isPending, startTransition] = useTransition();

  return (
    <a
      href={path}
      onClick={(e) => {
        e.preventDefault();
        startTransition(() => {
          setRoute(route);
        });
      }}
      {...props}
    >
      {isPending ? "Loading..." : children}
    </a>
  );
};

export default Router;
