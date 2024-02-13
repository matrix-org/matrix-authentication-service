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

import { RouterProvider, createRouter } from "@tanstack/react-router";
import { TooltipProvider } from "@vector-im/compound-web";
import { Provider } from "jotai";
import { Suspense, StrictMode } from "react";
import { createRoot } from "react-dom/client";
import { I18nextProvider } from "react-i18next";
import { Provider as UrqlProvider } from "urql";

import ErrorBoundary from "./components/ErrorBoundary";
import LoadingScreen from "./components/LoadingScreen";
import NotLoggedIn from "./components/NotLoggedIn";
import { client } from "./graphql";
import i18n from "./i18n";
import { routeTree } from "./routeTree.gen";
import "./main.css";
import { useCurrentUserId } from "./utils/useCurrentUserId";

// Create a new router instance
const router = createRouter({
  routeTree,
  basepath: "/account/",
  context: { userId: "", client },
});

// Register the router instance for type safety
declare module "@tanstack/react-router" {
  interface Register {
    router: typeof router;
  }
}

const App: React.FC = () => {
  const userId = useCurrentUserId();
  if (userId === null) return <NotLoggedIn />;

  return <RouterProvider router={router} context={{ userId, client }} />;
};

createRoot(document.getElementById("root") as HTMLElement).render(
  <StrictMode>
    <ErrorBoundary>
      <UrqlProvider value={client}>
        <Provider>
          <Suspense fallback={<LoadingScreen />}>
            <I18nextProvider i18n={i18n}>
              <TooltipProvider>
                <App />
              </TooltipProvider>
            </I18nextProvider>
          </Suspense>
        </Provider>
      </UrqlProvider>
    </ErrorBoundary>
  </StrictMode>,
);
