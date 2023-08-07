// Copyright 2023 The Matrix.org Foundation C.I.C.
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

import { Heading, Body, Avatar } from "@vector-im/compound-web";
import { useAtomValue } from "jotai";
import { atomFamily } from "jotai/utils";
import { atomWithQuery } from "jotai-urql";

import { graphql } from "../gql";

const QUERY = graphql(/* GraphQL */ `
  query UserGreeting($userId: ID!) {
    user(id: $userId) {
      id
      username
      matrix {
        mxid
        displayName
      }
    }
  }
`);

const userGreetingFamily = atomFamily((userId: string) => {
  const userGreeting = atomWithQuery({
    query: QUERY,
    getVariables: () => ({ userId }),
  });

  return userGreeting;
});

const UserGreeting: React.FC<{ userId: string }> = ({ userId }) => {
  const result = useAtomValue(userGreetingFamily(userId));

  if (result.data?.user) {
    const user = result.data.user;
    return (
      <header className="text-center">
        <Avatar
          size="var(--cpd-space-24x)"
          id={user.matrix.mxid}
          name={user.matrix.displayName || user.matrix.mxid}
        />
        <Heading size="xl" weight="semibold">
          {user.matrix.displayName || user.username}
        </Heading>
        <Body size="lg">{user.matrix.mxid}</Body>
      </header>
    );
  }

  return <>Failed to load user</>;
};

export default UserGreeting;
