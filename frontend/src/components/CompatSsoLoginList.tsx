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

import { graphql, useFragment } from "react-relay";
import CompatSsoLogin from "./CompatSsoLogin";
import { CompatSsoLoginList_user$key } from "./__generated__/CompatSsoLoginList_user.graphql";

type Props = {
  user: CompatSsoLoginList_user$key;
};

const CompatSsoLoginList: React.FC<Props> = ({ user }) => {
  const data = useFragment(
    graphql`
      fragment CompatSsoLoginList_user on User {
        compatSsoLogins(first: 10) {
          edges {
            node {
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
      {data.compatSsoLogins.edges.map((n) => (
        <CompatSsoLogin login={n.node} />
      ))}
    </div>
  );
};

export default CompatSsoLoginList;
