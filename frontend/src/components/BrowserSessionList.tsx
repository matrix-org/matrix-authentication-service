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
import { FragmentType, graphql, useFragment } from "../gql";

const FRAGMENT = graphql(/* GraphQL */ `
  fragment BrowserSessionList_user on User {
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
`);

type Props = {
  user: FragmentType<typeof FRAGMENT>;
  currentSessionId: string;
};

const BrowserSessionList: React.FC<Props> = ({ user, currentSessionId }) => {
  const data = useFragment(FRAGMENT, user);

  return (
    <BlockList>
      <Title>List of browser sessions:</Title>
      {data.browserSessions.edges.map((n) => (
        <BrowserSession
          key={n.cursor}
          session={n.node}
          isCurrent={n.node.id === currentSessionId}
        />
      ))}
    </BlockList>
  );
};

export default BrowserSessionList;
