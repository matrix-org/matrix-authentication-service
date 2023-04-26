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

import { atom, useAtomValue, useSetAtom } from "jotai";
import { atomWithQuery } from "jotai-urql";
import { atomFamily } from "jotai/utils";
import deepEqual from "fast-deep-equal";

import { graphql } from "../gql";
import { useTransition } from "react";
import Button from "./Button";
import UserEmail from "./UserEmail";
import BlockList from "./BlockList";

const QUERY = graphql(/* GraphQL */ `
  query UserEmailListQuery($userId: ID!, $first: Int!, $after: String) {
    user(id: $userId) {
      id
      emails(first: $first, after: $after) {
        edges {
          cursor
          node {
            id
            ...UserEmail_email
          }
        }
        pageInfo {
          hasNextPage
          endCursor
        }
      }
    }
  }
`);

const emailPageResultFamily = atomFamily(
  ({ userId, after }: { userId: string; after: string | null }) =>
    atomWithQuery({
      query: QUERY,
      getVariables: () => ({ userId, first: 5, after }),
    }),
  deepEqual
);

const emailPageListFamily = atomFamily((_userId: string) =>
  atom([null as string | null])
);

const emailNextPageFamily = atomFamily((userId: string) =>
  atom(null, (get, set, after: string) => {
    const currentList = get(emailPageListFamily(userId));
    set(emailPageListFamily(userId), [...currentList, after]);
  })
);

const emailPageFamily = atomFamily((userId: string) =>
  atom(async (get) => {
    const list = get(emailPageListFamily(userId));
    return await Promise.all(
      list.map((after) => get(emailPageResultFamily({ userId, after })))
    );
  })
);

const UserEmailList: React.FC<{ userId: string }> = ({ userId }) => {
  const [pending, startTransition] = useTransition();
  const result = useAtomValue(emailPageFamily(userId));
  const setLoadNextPage = useSetAtom(emailNextPageFamily(userId));
  const endPageInfo = result[result.length - 1]?.data?.user?.emails?.pageInfo;

  const loadNextPage = () => {
    if (endPageInfo?.hasNextPage && endPageInfo.endCursor) {
      const cursor = endPageInfo.endCursor;
      startTransition(() => {
        setLoadNextPage(cursor);
      });
    }
  };

  return (
    <BlockList>
      {result.flatMap(
        (page) =>
          page.data?.user?.emails?.edges?.map((edge) => (
            <UserEmail email={edge.node} key={edge.cursor} />
          )) || []
      )}
      {endPageInfo?.hasNextPage && (
        <Button compact ghost onClick={loadNextPage}>
          {pending ? "Loading..." : "Load more"}
        </Button>
      )}
    </BlockList>
  );
};

export default UserEmailList;
