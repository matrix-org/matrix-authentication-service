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
import { atomWithQuery } from "jotai-urql";

import { mapQueryAtom } from "../atoms";
import GraphQLError from "../components/GraphQLError";
import NotLoggedIn from "../components/NotLoggedIn";
import UserHome from "../components/UserHome";
import { graphql } from "../gql";
import { isErr, unwrapErr, unwrapOk } from "../result";

const QUERY = graphql(/* GraphQL */ `
  query SessionsOverviewQuery {
    viewer {
      __typename

      ... on User {
        id
        ...UserHome_user
      }
    }
  }
`);

const sessionsOverviewQueryAtom = atomWithQuery({
  query: QUERY,
});

const sessionsOverviewAtom = mapQueryAtom(sessionsOverviewQueryAtom, (data) => {
  if (data.viewer?.__typename === "User") {
    return data.viewer;
  }

  return null;
});

const SessionsOverview: React.FC = () => {
  const result = useAtomValue(sessionsOverviewAtom);
  if (isErr(result)) return <GraphQLError error={unwrapErr(result)} />;

  const data = unwrapOk(result);
  if (data === null) return <NotLoggedIn />;

  return <UserHome user={data} />;
};

export default SessionsOverview;
