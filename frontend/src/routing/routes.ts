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

export type Location = Readonly<{
  pathname: string;
  searchParams?: URLSearchParams;
}>;

export type Segments = Readonly<string[]>;

// Converts a list of segments to a path
const segmentsToPath = (segments: Segments): string =>
  segments.map((part) => encodeURIComponent(part)).join("/");

// Converts a path to a list of segments
const pathToSegments = (path: string): Segments =>
  path.split("/").map(decodeURIComponent);

type ProfileRoute = Readonly<{ type: "profile" }>;
type SessionOverviewRoute = Readonly<{ type: "sessions-overview" }>;
type SessionDetailRoute = Readonly<{ type: "session"; id: string }>;
type OAuth2ClientRoute = Readonly<{ type: "client"; id: string }>;
type BrowserSessionRoute = Readonly<{ type: "browser-session"; id: string }>;
type BrowserSessionListRoute = Readonly<{ type: "browser-session-list" }>;
type VerifyEmailRoute = Readonly<{ type: "verify-email"; id: string }>;
type UnknownRoute = Readonly<{ type: "unknown"; segments: Segments }>;

export type Route =
  | SessionOverviewRoute
  | SessionDetailRoute
  | ProfileRoute
  | OAuth2ClientRoute
  | BrowserSessionRoute
  | BrowserSessionListRoute
  | VerifyEmailRoute
  | UnknownRoute;

// Converts a route to a path
export const routeToPath = (route: Route): string =>
  segmentsToPath(routeToSegments(route));

// Converts a path to a route
export const pathToRoute = (path: string): Route =>
  segmentsToRoute(pathToSegments(path));

// Converts a route to a list of segments
export const routeToSegments = (route: Route): Segments => {
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
    case "unknown":
      return route.segments;
  }
};

const P = Symbol();
type PatternItem = string | typeof P;

// Returns true if the segments match the pattern, where P is a parameter
const segmentMatches = (
  segments: Segments,
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

// Converts a list of segments to a route
export const segmentsToRoute = (segments: Segments): Route => {
  const matches = (...pattern: PatternItem[]): boolean =>
    segmentMatches(segments, ...pattern);

  // Special case for the home page
  if (matches() || matches("")) {
    return { type: "profile" };
  }

  if (matches("sessions-overview")) {
    return { type: "sessions-overview" };
  }

  if (matches("browser-sessions")) {
    return { type: "browser-session-list" };
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
