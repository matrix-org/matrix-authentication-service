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

import { Provider } from "jotai";
import { DevTools } from "jotai-devtools";
import { Suspense, StrictMode } from "react";
import { createRoot } from "react-dom/client";

import Router from "./Router";
import { HydrateAtoms } from "./atoms";
import LoadingScreen from "./components/LoadingScreen";

createRoot(document.getElementById("root") as HTMLElement).render(
  <StrictMode>
    <Provider>
      {import.meta.env.DEV && <DevTools />}
      <HydrateAtoms>
        <Suspense fallback={<LoadingScreen />}>
          <Router />
        </Suspense>
      </HydrateAtoms>
    </Provider>
  </StrictMode>
);
