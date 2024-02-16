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

import { createFileRoute, notFound } from "@tanstack/react-router";
import { useQuery } from "urql";

import UserSessionsOverview from "../components/UserSessionsOverview";
import { graphql } from "../gql";

const QUERY = graphql(/* GraphQL */ `
  query SessionsOverviewQuery {
    viewer {
      __typename

      ... on User {
        id
        ...BrowserSessionsOverview_user
      }
    }
  }
`);

export const Route = createFileRoute("/_account/sessions/")({
  async loader({ context, abortController: { signal } }) {
    const result = await context.client.query(
      QUERY,
      {},
      { fetchOptions: { signal } },
    );
    if (result.error) throw result.error;
    if (result.data?.viewer?.__typename !== "User") throw notFound();
  },
  component: Sessions,
});

function Sessions(): React.ReactElement {
  const [result] = useQuery({ query: QUERY });
  if (result.error) throw result.error;
  const data =
    result.data?.viewer.__typename === "User" ? result.data.viewer : null;
  if (data === null) throw notFound();

  return <UserSessionsOverview user={data} />;
}
