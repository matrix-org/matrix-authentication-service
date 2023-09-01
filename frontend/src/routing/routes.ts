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

export type Location = {
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
