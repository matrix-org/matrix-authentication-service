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

import { useQuery } from "urql";

import ErrorBoundary from "../components/ErrorBoundary";
import GraphQLError from "../components/GraphQLError";
import NotLoggedIn from "../components/NotLoggedIn";
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

const SessionsOverview: React.FC = () => {
  const [result] = useQuery({ query: QUERY });
  if (result.error) return <GraphQLError error={result.error} />;
  if (!result.data) throw new Error(); // Suspense mode is enabled

  const data =
    result.data.viewer.__typename === "User" ? result.data.viewer : null;
  if (data === null) return <NotLoggedIn />;

  return (
    <ErrorBoundary>
      <UserSessionsOverview user={data} />
    </ErrorBoundary>
  );
};

export default SessionsOverview;
