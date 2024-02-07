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

import { HydrateAtoms } from "./atoms";
import Layout from "./components/Layout";
import LoadingScreen from "./components/LoadingScreen";
import LoadingSpinner from "./components/LoadingSpinner";
import i18n from "./i18n";
import { Router } from "./routing";
import "./main.css";

createRoot(document.getElementById("root") as HTMLElement).render(
  <StrictMode>
    <Provider>
      {import.meta.env.DEV && <DevTools />}
      <HydrateAtoms>
        <Suspense fallback={<LoadingScreen />}>
          <I18nextProvider i18n={i18n}>
            <TooltipProvider>
              <Layout>
                <Suspense fallback={<LoadingSpinner />}>
                  <Router />
                </Suspense>
              </Layout>
            </TooltipProvider>
          </I18nextProvider>
        </Suspense>
      </HydrateAtoms>
    </Provider>
  </StrictMode>,
);
