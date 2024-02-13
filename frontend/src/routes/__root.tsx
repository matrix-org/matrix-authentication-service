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

import { createRootRouteWithContext, Outlet } from "@tanstack/react-router";
import { TanStackRouterDevtools } from "@tanstack/router-devtools";
import { Client, useQuery } from "urql";

import Layout from "../components/Layout";
import { graphql } from "../gql";

const QUERY = graphql(/* GraphQL */ `
  query UserLayout($userId: ID!) {
    user(id: $userId) {
      ...UserGreeting_user
    }
  }
`);

export const Route = createRootRouteWithContext<{
  userId: string;
  client: Client;
}>()({
  loader: ({ context }) => {
    return context.userId;
  },
  component: RootComponent,
});

function RootComponent(): React.ReactElement {
  const userId = Route.useLoaderData();
  const [result] = useQuery({
    query: QUERY,
    variables: { userId },
  });
  if (result.error) throw result.error;
  const user = result.data?.user;
  if (!user) throw new Error(); // Suspense mode is enabled

  return (
    <>
      <Layout user={user}>
        <Outlet />
      </Layout>
      <TanStackRouterDevtools />
    </>
  );
}
