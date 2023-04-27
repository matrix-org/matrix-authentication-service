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
import UserEmail from "./UserEmail";
import BlockList from "./BlockList";
import PaginationControls from "./PaginationControls";
import { atomWithPagination, pageSizeAtom, Pagination } from "../pagination";
import { PageInfo } from "../gql/graphql";

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

const currentPagination = atomWithDefault<Pagination>((get) => ({
  first: get(pageSizeAtom),
  after: null,
}));

export const emailPageResultFamily = atomFamily((userId: string) => {
  const emailPageResult = atomWithQuery({
    query: QUERY,
    getVariables: (get) => ({ userId, ...get(currentPagination) }),
  });
  return emailPageResult;
});

const pageInfoFamily = atomFamily((userId: string) => {
  const pageInfoAtom = atom(async (get): Promise<PageInfo | null> => {
    const result = await get(emailPageResultFamily(userId));
    return result.data?.user?.emails?.pageInfo ?? null;
  });

  return pageInfoAtom;
});

const paginationFamily = atomFamily((userId: string) => {
  const paginationAtom = atomWithPagination(
    currentPagination,
    pageInfoFamily(userId)
  );
  return paginationAtom;
});

const UserEmailList: React.FC<{ userId: string }> = ({ userId }) => {
  const [pending, startTransition] = useTransition();
  const result = useAtomValue(emailPageResultFamily(userId));
  const setPagination = useSetAtom(currentPagination);
  const [prevPage, nextPage] = useAtomValue(paginationFamily(userId));

  const paginate = (pagination: Pagination) => {
    startTransition(() => {
      setPagination(pagination);
    });
  };

  return (
    <BlockList>
      <PaginationControls
        count={result.data?.user?.emails?.totalCount ?? 0}
        onPrev={prevPage ? () => paginate(prevPage) : null}
        onNext={nextPage ? () => paginate(nextPage) : null}
        disabled={pending}
      />
      {result.data?.user?.emails?.edges?.map((edge) => (
        <UserEmail email={edge.node} key={edge.cursor} />
      ))}
    </BlockList>
  );
};

export default UserEmailList;
