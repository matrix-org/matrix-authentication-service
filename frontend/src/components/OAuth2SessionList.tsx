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
import OAuth2Session from "./OAuth2Session";
import { Title } from "./Typography";

import { FragmentType, graphql, useFragment } from "../gql";

const FRAGMENT = graphql(/* GraphQL */ `
  fragment OAuth2SessionList_user on User {
    oauth2Sessions(first: $count, after: $cursor) {
      edges {
        cursor
        node {
          id
          ...OAuth2Session_session
        }
      }
    }
  }
`);

type Props = {
  user: FragmentType<typeof FRAGMENT>;
};

const OAuth2SessionList: React.FC<Props> = ({ user }) => {
  const data = useFragment(FRAGMENT, user);

  return (
    <BlockList>
      <Title>List of OAuth 2.0 sessions:</Title>
      {data.oauth2Sessions.edges.map((n) => (
        <OAuth2Session key={n.cursor} session={n.node} />
      ))}
    </BlockList>
  );
};

export default OAuth2SessionList;
