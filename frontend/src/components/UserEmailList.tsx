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
import { atomFamily, atomWithDefault } from "jotai/utils";

import { graphql } from "../gql";
import { useTransition } from "react";
import Button from "./Button";
import UserEmail from "./UserEmail";
import BlockList from "./BlockList";

const QUERY = graphql(/* GraphQL */ `
  query UserEmailListQuery(
    $userId: ID!
    $first: Int
    $after: String
    $last: Int
    $before: String
  ) {
    user(id: $userId) {
      id
      emails(first: $first, after: $after, last: $last, before: $before) {
        edges {
          cursor
          node {
            id
            ...UserEmail_email
          }
        }
        totalCount
        pageInfo {
          hasNextPage
          hasPreviousPage
          startCursor
          endCursor
        }
      }
    }
  }
`);

type ForwardPagination = {
  first: number;
  after: string | null;
};

type BackwardPagination = {
  last: number;
  before: string | null;
};

type Pagination = ForwardPagination | BackwardPagination;

const isForwardPagination = (
  pagination: Pagination
): pagination is ForwardPagination => {
  return pagination.hasOwnProperty("first");
};

const isBackwardPagination = (
  pagination: Pagination
): pagination is BackwardPagination => {
  return pagination.hasOwnProperty("last");
};

const pageSize = atom(6);

const currentPagination = atomWithDefault<Pagination>((get) => ({
  first: get(pageSize),
  after: null,
}));

export const emailPageResultFamily = atomFamily((userId: string) => {
  const emailPageResult = atomWithQuery({
    query: QUERY,
    getVariables: (get) => ({ userId, ...get(currentPagination) }),
  });
  return emailPageResult;
});

const nextPagePaginationFamily = atomFamily((userId: string) => {
  const nextPagePagination = atom(
    async (get): Promise<ForwardPagination | null> => {
      // If we are paginating backwards, we can assume there is a next page
      const pagination = get(currentPagination);
      const hasProbablyNextPage =
        isBackwardPagination(pagination) && pagination.before !== null;

      const result = await get(emailPageResultFamily(userId));
      const pageInfo = result.data?.user?.emails?.pageInfo;
      if (pageInfo?.hasNextPage || hasProbablyNextPage) {
        return {
          first: get(pageSize),
          after: pageInfo?.endCursor ?? null,
        };
      }

      return null;
    }
  );
  return nextPagePagination;
});

const prevPagePaginationFamily = atomFamily((userId: string) => {
  const prevPagePagination = atom(
    async (get): Promise<BackwardPagination | null> => {
      // If we are paginating forwards, we can assume there is a previous page
      const pagination = get(currentPagination);
      const hasProbablyPreviousPage =
        isForwardPagination(pagination) && pagination.after !== null;

      const result = await get(emailPageResultFamily(userId));
      const pageInfo = result.data?.user?.emails?.pageInfo;
      if (pageInfo?.hasPreviousPage || hasProbablyPreviousPage) {
        return {
          last: get(pageSize),
          before: pageInfo?.startCursor ?? null,
        };
      }

      return null;
    }
  );
  return prevPagePagination;
});

const UserEmailList: React.FC<{ userId: string }> = ({ userId }) => {
  const [pending, startTransition] = useTransition();
  const result = useAtomValue(emailPageResultFamily(userId));
  const setPagination = useSetAtom(currentPagination);
  const nextPagePagination = useAtomValue(nextPagePaginationFamily(userId));
  const prevPagePagination = useAtomValue(prevPagePaginationFamily(userId));

  const paginate = (pagination: Pagination) => {
    startTransition(() => {
      setPagination(pagination);
    });
  };

  return (
    <div>
      <div className="grid items-center grid-cols-3 gap-2 mb-2">
        {prevPagePagination ? (
          <Button
            compact
            disabled={pending}
            ghost
            onClick={() => paginate(prevPagePagination)}
          >
            Previous
          </Button>
        ) : (
          <Button compact disabled ghost>
            Previous
          </Button>
        )}
        <div className="text-center">
          Total: {result.data?.user?.emails?.totalCount}
        </div>
        {nextPagePagination ? (
          <Button
            compact
            disabled={pending}
            ghost
            onClick={() => paginate(nextPagePagination)}
          >
            Next
          </Button>
        ) : (
          <Button compact disabled ghost>
            Next
          </Button>
        )}
      </div>
      <BlockList>
        {result.data?.user?.emails?.edges?.map((edge) => (
          <UserEmail email={edge.node} key={edge.cursor} />
        ))}
      </BlockList>
    </div>
  );
};

export default UserEmailList;
