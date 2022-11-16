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

import { graphql, usePaginationFragment } from "react-relay";
import BlockList from "./BlockList";
import Button from "./Button";
import OAuth2Session from "./OAuth2Session";
import { Title } from "./Typography";

import { OAuth2SessionList_user$key } from "./__generated__/OAuth2SessionList_user.graphql";

type Props = {
  user: OAuth2SessionList_user$key;
};

const OAuth2SessionList: React.FC<Props> = ({ user }) => {
  const { data, loadNext, hasNext } = usePaginationFragment(
    graphql`
      fragment OAuth2SessionList_user on User
      @refetchable(queryName: "OAuth2SessionListQuery") {
        oauth2Sessions(first: $count, after: $cursor)
          @connection(key: "OAuth2SessionList_user_oauth2Sessions") {
          edges {
            cursor
            node {
              id
              ...OAuth2Session_session
            }
          }
        }
      }
    `,
    user
  );

  return (
    <BlockList>
      <Title>List of OAuth 2.0 sessions:</Title>
      {data.oauth2Sessions.edges.map((n) => (
        <OAuth2Session key={n.cursor} session={n.node} />
      ))}
      {hasNext && <Button onClick={() => loadNext(2)}>Load more</Button>}
    </BlockList>
  );
};

export default OAuth2SessionList;
