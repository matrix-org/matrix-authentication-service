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

import { TooltipProvider } from "@vector-im/compound-web";
import { Provider } from "jotai";
import { DevTools } from "jotai-devtools";
import { Suspense, StrictMode } from "react";
import { createRoot } from "react-dom/client";
import { I18nextProvider } from "react-i18next";
import { Provider as UrqlProvider } from "urql";

import { HydrateAtoms, useCurrentUserId } from "./atoms";
import ErrorBoundary from "./components/ErrorBoundary";
import Layout from "./components/Layout";
import LoadingScreen from "./components/LoadingScreen";
import LoadingSpinner from "./components/LoadingSpinner";
import NotLoggedIn from "./components/NotLoggedIn";
import { client } from "./graphql";
import i18n from "./i18n";
import { Router } from "./routing";
import "./main.css";

const App: React.FC = () => {
  const userId = useCurrentUserId();
  if (userId === null) return <NotLoggedIn />;

  return (
    <Layout userId={userId}>
      <Suspense fallback={<LoadingSpinner />}>
        <Router userId={userId} />
      </Suspense>
    </Layout>
  );
};

createRoot(document.getElementById("root") as HTMLElement).render(
  <StrictMode>
    <ErrorBoundary>
      <UrqlProvider value={client}>
        <Provider>
          {import.meta.env.DEV && <DevTools />}
          <HydrateAtoms>
            <Suspense fallback={<LoadingScreen />}>
              <I18nextProvider i18n={i18n}>
                <TooltipProvider>
                  <App />
                </TooltipProvider>
              </I18nextProvider>
            </Suspense>
          </HydrateAtoms>
        </Provider>
      </UrqlProvider>
    </ErrorBoundary>
  </StrictMode>,
);
