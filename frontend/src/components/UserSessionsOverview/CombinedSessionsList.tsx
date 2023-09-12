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

import { mapQueryAtom } from "../../atoms";
import { graphql } from "../../gql";
import {
  BrowserSessionState,
  CompatSessionState,
  Oauth2SessionState,
} from "../../gql/graphql";
import { isErr, unwrapErr, unwrapOk } from "../../result";
import BlockList from "../BlockList";
import SessionList from "../SessionList/SessionList";

const QUERY = graphql(/* GraphQL */ `
  query BrowserSessionList2(
    $userId: ID!
    $state: BrowserSessionState
    $compatState: CompatSessionState
    $oauthState: Oauth2SessionState
  ) {
    user(id: $userId) {
      id
      browserSessions(first: 6, state: $state) {
        totalCount

        edges {
          cursor
          node {
            id
            ...BrowserSession_session
          }
        }
      }
      compatSessions(first: 6, state: $compatState) {
        totalCount
        edges {
          cursor
          node {
            id
            ...CompatSession_session
          }
        }
      }
      oauth2Sessions(state: $oauthState, first: 6) {
        edges {
          cursor
          node {
            id
            ...OAuth2Session_session
          }
        }

        totalCount
      }
    }
  }
`);

const browserSessionListFamily = atomFamily((userId: string) => {
  const browserSessionListQuery = atomWithQuery({
    query: QUERY,
    getVariables: (get) => ({
      userId,
      state: BrowserSessionState.Active,
      compatState: CompatSessionState.Active,
      oauthState: Oauth2SessionState.Active,
    }),
  });

  const browserSessionList = mapQueryAtom(browserSessionListQuery, (data) => {
    const browserSessions = data.user?.browserSessions.edges || [];
    const compatSessions = data.user?.compatSessions.edges || [];
    const oauth2Sessions = data.user?.oauth2Sessions.edges || [];
    return [...browserSessions, ...compatSessions, ...oauth2Sessions].sort(
      (a, b) => (a.node.createdAt > b.node.createdAt ? -1 : 1),
    );
  });

  return browserSessionList;
});

const CombinedSessionsList: React.FC<{ userId: string }> = ({ userId }) => {
  const result = useAtomValue(browserSessionListFamily(userId));

  if (isErr(result)) throw unwrapErr(result);

  const sessions = unwrapOk(result);
  if (sessions === null) return <>Failed to load browser sessions</>;

  console.log("hhh", sessions);

  return (
    <BlockList>
      <SessionList sessionEdges={sessions} />
    </BlockList>
  );
};

export default CombinedSessionsList;
