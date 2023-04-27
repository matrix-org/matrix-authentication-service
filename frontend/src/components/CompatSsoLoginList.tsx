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
import CompatSsoLogin from "./CompatSsoLogin";
import { Title } from "./Typography";
import { graphql } from "../gql";
import { atomFamily } from "jotai/utils";
import { atomWithQuery } from "jotai-urql";
import { useAtomValue } from "jotai";

const QUERY = graphql(/* GraphQL */ `
  query CompatSsoLoginList($userId: ID!) {
    user(id: $userId) {
      id
      compatSsoLogins(first: 10) {
        edges {
          node {
            id
            ...CompatSsoLogin_login
          }
        }
      }
    }
  }
`);

const compatSsoLoginListFamily = atomFamily((userId: string) => {
  const compatSsoLoginList = atomWithQuery({
    query: QUERY,
    getVariables: () => ({ userId }),
  });

  return compatSsoLoginList;
});

const CompatSsoLoginList: React.FC<{ userId: string }> = ({ userId }) => {
  const result = useAtomValue(compatSsoLoginListFamily(userId));

  if (result.data?.user?.compatSsoLogins) {
    const data = result.data.user.compatSsoLogins;
    return (
      <BlockList>
        <Title>List of compatibility sessions:</Title>
        {data.edges.map((n) => (
          <CompatSsoLogin login={n.node} key={n.node.id} />
        ))}
      </BlockList>
    );
  }

  return <>Failed to load list of compatibility sessions.</>;
};

export default CompatSsoLoginList;
