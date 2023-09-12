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

import { H3, Body } from "@vector-im/compound-web";
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
import Link from "../../routing/Link";
import BlockList from "../BlockList";
import SessionList from "../SessionList/SessionList";

const QUERY = graphql(/* GraphQL */ `
  query BadCombinedSessionList(
    $userId: ID!
    $state: BrowserSessionState
    $compatState: CompatSessionState
    $oauthState: Oauth2SessionState
  ) {
    user(id: $userId) {
      id
      browserSessions(last: 6, state: $state) {
        totalCount

        edges {
          cursor
          node {
            id
            ...BrowserSession_session
          }
        }
      }
      compatSessions(last: 6, state: $compatState) {
        totalCount
        edges {
          cursor
          node {
            id
            ...CompatSession_session
          }
        }
      }
      oauth2Sessions(state: $oauthState, last: 6) {
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

const badCombinedSessionListFamily = atomFamily((userId: string) => {
  const badCombinedSessionListQuery = atomWithQuery({
    query: QUERY,
    getVariables: (get) => ({
      userId,
      state: BrowserSessionState.Active,
      compatState: CompatSessionState.Active,
      oauthState: Oauth2SessionState.Active,
    }),
  });

  const badCombinedSessionList = mapQueryAtom(
    badCombinedSessionListQuery,
    (data) => {
      const browserSessions = data.user?.browserSessions || {};
      const compatSessions = data.user?.compatSessions || {};
      const oauth2Sessions = data.user?.oauth2Sessions || {};
      const sessions = [
        ...(browserSessions.edges || []),
        ...(compatSessions.edges || []),
        ...(oauth2Sessions.edges || []),
      ].sort((a, b) => (a.node.createdAt > b.node.createdAt ? -1 : 1));

      const totalCount =
        browserSessions.totalCount +
        compatSessions.totalCount +
        oauth2Sessions.totalCount;

      return {
        sessions,
        totalCount,
        browserSessions,
        compatSessions,
        oauth2Sessions,
      };
    },
  );

  return badCombinedSessionList;
});

const CombinedSessionsList: React.FC<{ userId: string }> = ({ userId }) => {
  const result = useAtomValue(badCombinedSessionListFamily(userId));

  if (isErr(result)) throw unwrapErr(result);

  const {
    sessions,
    totalCount,
    browserSessions,
    compatSessions,
    oauth2Sessions,
  } = unwrapOk(result);
  if (!sessions) return <>Failed to load browser sessions</>;

  const subtitle = (
    <>
      {`You're signed in to ${totalCount} sessions:`}
      <Link kind="button" route={{ type: "browser-session-list" }}>
        {`${browserSessions.totalCount} browsers, `}
      </Link>
      <Link kind="button" route={{ type: "compat-session-list" }}>
        {`${compatSessions.totalCount} regular apps, `}
      </Link>
      and
      <Link kind="button" route={{ type: "oauth2-session-list" }}>
        {`${oauth2Sessions.totalCount} new apps`}
      </Link>
    </>
  );

  return (
    <BlockList>
      <H3>Where you're signed in</H3>
      <Body>{subtitle}</Body>
      <SessionList sessionEdges={sessions} />
    </BlockList>
  );
};

export default CombinedSessionsList;
