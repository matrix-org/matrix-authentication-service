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

import { useAtomValue } from "jotai";
import { atomFamily } from "jotai/utils";
import { atomWithQuery } from "jotai-urql";

import { mapQueryAtom } from "../atoms";
import GraphQLError from "../components/GraphQLError";
import NotFound from "../components/NotFound";
import { graphql } from "../gql";
import { isErr, unwrapErr, unwrapOk } from "../result";

const QUERY = graphql(/* GraphQL */ `
  query OAuth2ClientQuery($id: ID!) {
    oauth2Client(id: $id) {
      id
      clientId
      clientName
      clientUri
      tosUri
      policyUri
      redirectUris
    }
  }
`);

const oauth2ClientFamily = atomFamily((id: string) => {
  const oauth2ClientQueryAtom = atomWithQuery({
    query: QUERY,
    getVariables: () => ({ id }),
  });

  const oauth2ClientAtom = mapQueryAtom(
    oauth2ClientQueryAtom,
    (data) => data?.oauth2Client,
  );

  return oauth2ClientAtom;
});

const OAuth2Client: React.FC<{ id: string }> = ({ id }) => {
  const result = useAtomValue(oauth2ClientFamily(id));
  if (isErr(result)) return <GraphQLError error={unwrapErr(result)} />;

  const oauth2Client = unwrapOk(result);
  if (oauth2Client === null) return <NotFound />;

  return (
    <pre>
      <code>{JSON.stringify(oauth2Client, null, 2)}</code>
    </pre>
  );
};

export default OAuth2Client;
