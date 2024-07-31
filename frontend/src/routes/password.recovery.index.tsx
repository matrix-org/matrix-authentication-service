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

import { createFileRoute } from "@tanstack/react-router";

import { graphql } from "../gql";

export const QUERY = graphql(/* GraphQL */ `
  query PasswordRecoveryQuery {
    siteConfig {
      id
      ...PasswordCreationDoubleInput_siteConfig
    }
  }
`);

export const Route = createFileRoute("/password/recovery/")({
  validateSearch: (search) =>
    search as {
      ticket: string;
    },
  async loader({ context, abortController: { signal } }) {
    const queryResult = await context.client.query(
      QUERY,
      {},
      { fetchOptions: { signal } },
    );
    if (queryResult.error) throw queryResult.error;
  },
});
