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

import OAuth2ClientDetail from "../components/Client/OAuth2ClientDetail";
import ErrorBoundary from "../components/ErrorBoundary";
import GraphQLError from "../components/GraphQLError";
import NotFound from "../components/NotFound";
import { graphql } from "../gql";

const QUERY = graphql(/* GraphQL */ `
  query OAuth2ClientQuery($id: ID!) {
    oauth2Client(id: $id) {
      ...OAuth2Client_detail
    }
  }
`);

const OAuth2Client: React.FC<{ id: string }> = ({ id }) => {
  const [result] = useQuery({
    query: QUERY,
    variables: { id },
  });
  if (result.error) return <GraphQLError error={result.error} />;
  if (!result.data) throw new Error(); // Suspense mode is enabled

  const oauth2Client = result.data.oauth2Client;
  if (!oauth2Client) return <NotFound />;

  return (
    <ErrorBoundary>
      <OAuth2ClientDetail client={oauth2Client} />
    </ErrorBoundary>
  );
};

export default OAuth2Client;
