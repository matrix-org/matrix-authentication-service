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

import { Form } from "@vector-im/compound-web";
import { Suspense, StrictMode } from "react";
import { createRoot } from "react-dom/client";
import { I18nextProvider } from "react-i18next";
import { Provider as UrqlProvider } from "urql";

import ErrorBoundary from "./components/ErrorBoundary";
import LoadingScreen from "./components/LoadingScreen";
import { client } from "./graphql";
import i18n from "./i18n";
import "./shared.css";

createRoot(document.getElementById("recovery-form") as HTMLElement).render(
  <StrictMode>
    <UrqlProvider value={client}>
      <ErrorBoundary>
        <Suspense fallback={<LoadingScreen />}>
          <I18nextProvider i18n={i18n}>
            <Form.Root method="POST">
              <Form.Field name="password">
                <Form.Label>Password</Form.Label>
                <Form.PasswordControl />
              </Form.Field>
              <Form.Field name="password_confirm">
                <Form.Label>Confirm password</Form.Label>
                <Form.PasswordControl />
              </Form.Field>
              <Form.Submit>Submit</Form.Submit>
            </Form.Root>
          </I18nextProvider>
        </Suspense>
      </ErrorBoundary>
    </UrqlProvider>
  </StrictMode>,
);
