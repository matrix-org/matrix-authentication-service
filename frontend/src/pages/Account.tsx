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

import React from "react";
import { useAtomValue } from "jotai";
import { atomFamily } from "jotai/utils";
import { atomWithQuery } from "jotai-urql";

import { graphql } from "../gql";
import UserEmailList from "../components/UserEmailList";
import { Title } from "../components/Typography";
import AddEmailForm from "../components/AddEmailForm";

const CURRENT_USER_QUERY = graphql(/* GraphQL */ `
  query CurrentUserQuery {
    viewer {
      ... on User {
        __typename
        id
      }
    }
  }
`);

const currentUserAtom = atomWithQuery({ query: CURRENT_USER_QUERY });

const QUERY = graphql(/* GraphQL */ `
  query AccountQuery($id: ID!) {
    user(id: $id) {
      id
      username
    }
  }
`);

const accountAtomFamily = atomFamily((id: string) =>
  atomWithQuery({ query: QUERY, getVariables: () => ({ id }) })
);

const UserAccount: React.FC<{ id: string }> = ({ id }) => {
  const result = useAtomValue(accountAtomFamily(id));

  return (
    <div className="grid grid-cols-1 gap-4">
      <Title>Hello {result.data?.user?.username}</Title>
      <UserEmailList userId={id} />
      <AddEmailForm userId={id} />
    </div>
  );
};

const CurrentUserAccount: React.FC = () => {
  const result = useAtomValue(currentUserAtom);
  if (result.data?.viewer?.__typename === "User") {
    return (
      <div className="w-96 mx-auto">
        <UserAccount id={result.data.viewer.id} />
      </div>
    );
  }

  return <div className="w-96 mx-auto">Not logged in.</div>;
};

export default CurrentUserAccount;
