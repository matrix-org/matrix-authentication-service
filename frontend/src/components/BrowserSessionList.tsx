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

import BlockList from "./BlockList";
import BrowserSession from "./BrowserSession";
import { Title } from "./Typography";
import { graphql } from "../gql";
import { atomFamily } from "jotai/utils";
import { atomWithQuery } from "jotai-urql";
import { useAtomValue } from "jotai";
import { currentBrowserSessionIdAtom } from "../atoms";

const QUERY = graphql(/* GraphQL */ `
  query BrowserSessionList($userId: ID!) {
    user(id: $userId) {
      id
      browserSessions(first: 10) {
        edges {
          cursor
          node {
            id
            ...BrowserSession_session
          }
        }
      }
    }
  }
`);

const browserSessionListFamily = atomFamily((userId: string) => {
  const browserSessionList = atomWithQuery({
    query: QUERY,
    getVariables: () => ({ userId }),
  });
  return browserSessionList;
});

const BrowserSessionList: React.FC<{ userId: string }> = ({ userId }) => {
  const result = useAtomValue(browserSessionListFamily(userId));
  const currentSessionId = useAtomValue(currentBrowserSessionIdAtom);

  if (result.data?.user?.browserSessions) {
    const data = result.data.user.browserSessions;
    return (
      <BlockList>
        <Title>List of browser sessions:</Title>
        {data.edges.map((n) => (
          <BrowserSession
            key={n.cursor}
            session={n.node}
            isCurrent={n.node.id === currentSessionId}
          />
        ))}
      </BlockList>
    );
  }

  return <>Failed to load browser sessions</>;
};

export default BrowserSessionList;
