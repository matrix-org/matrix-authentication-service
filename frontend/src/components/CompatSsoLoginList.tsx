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
import Button from "./Button";
import CompatSsoLogin from "./CompatSsoLogin";
import { CompatSsoLoginList_user$key } from "./__generated__/CompatSsoLoginList_user.graphql";

type Props = {
  user: CompatSsoLoginList_user$key;
};

const CompatSsoLoginList: React.FC<Props> = ({ user }) => {
  const { data, loadNext, hasNext } = usePaginationFragment(
    graphql`
      fragment CompatSsoLoginList_user on User
      @refetchable(queryName: "CompatSsoLoginListQuery") {
        compatSsoLogins(first: $count, after: $cursor)
          @connection(key: "CompatSsoLoginList_user_compatSsoLogins") {
          edges {
            node {
              id
              ...CompatSsoLogin_login
            }
          }
        }
      }
    `,
    user
  );

  return (
    <div>
      <h2 className="text-lg">List of compatibility sessions:</h2>
      {data.compatSsoLogins.edges.map((n) => (
        <CompatSsoLogin login={n.node} key={n.node.id} />
      ))}
      {hasNext && <Button onClick={() => loadNext(2)}>Load more</Button>}
    </div>
  );
};

export default CompatSsoLoginList;
