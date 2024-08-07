// Copyright 2024 The Matrix.org Foundation C.I.C.
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

import {
  RouterContextProvider,
  createMemoryHistory,
  createRootRoute,
  createRoute,
  createRouter,
} from "@tanstack/react-router";

const rootRoute = createRootRoute();
const index = createRoute({ getParentRoute: () => rootRoute, path: "/" });

const router = createRouter({
  history: createMemoryHistory(),
  routeTree: rootRoute.addChildren([index]),
});

export const DummyRouter: React.FC<React.PropsWithChildren> = ({
  children,
}) => (
  /** @ts-expect-error: The router we pass doesn't match the "real" router, which is fine for tests */
  <RouterContextProvider router={router}>{children}</RouterContextProvider>
);
