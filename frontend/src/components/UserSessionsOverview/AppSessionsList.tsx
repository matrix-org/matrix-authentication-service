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

import { H6, Text } from "@vector-im/compound-web";
import { atom, useAtomValue, useSetAtom } from "jotai";
import { atomFamily } from "jotai/utils";
import { atomWithQuery } from "jotai-urql";
import { useTransition } from "react";

import { mapQueryAtom } from "../../atoms";
import { graphql } from "../../gql";
import { SessionState, PageInfo } from "../../gql/graphql";
import {
  atomForCurrentPagination,
  atomWithPagination,
  Pagination,
} from "../../pagination";
import { isOk, unwrap, unwrapOk } from "../../result";
import BlockList from "../BlockList";
import PaginationControls from "../PaginationControls";

const QUERY = graphql(/* GraphQL */ `
  query AppSessionList(
    $userId: ID!
    $state: SessionState
    $first: Int
    $after: String
    $last: Int
    $before: String
  ) {
    user(id: $userId) {
      id
      appSessions(
        first: $first
        after: $after
        last: $last
        before: $before
        state: $state
      ) {
        totalCount

        edges {
          cursor
          node {
            ...CompatSession_session
            ...OAuth2Session_session
          }
        }

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

const filterAtom = atom<SessionState | null>(SessionState.Active);
const currentPaginationAtom = atomForCurrentPagination();

const appSessionListFamily = atomFamily((userId: string) => {
  const appSessionListQuery = atomWithQuery({
    query: QUERY,
    getVariables: (get) => ({
      userId,
      state: get(filterAtom),
      ...get(currentPaginationAtom),
    }),
  });

  const appSessionList = mapQueryAtom(
    appSessionListQuery,
    (data) => data.user?.appSessions || null,
  );

  return appSessionList;
});

const pageInfoFamily = atomFamily((userId: string) => {
  const pageInfoAtom = atom(async (get): Promise<PageInfo | null> => {
    const result = await get(appSessionListFamily(userId));
    return (isOk(result) && unwrapOk(result)?.pageInfo) || null;
  });
  return pageInfoAtom;
});

const paginationFamily = atomFamily((userId: string) => {
  const paginationAtom = atomWithPagination(
    currentPaginationAtom,
    pageInfoFamily(userId),
  );

  return paginationAtom;
});

const AppSessionsList: React.FC<{ userId: string }> = ({ userId }) => {
  const [pending, startTransition] = useTransition();
  const result = useAtomValue(appSessionListFamily(userId));
  const setPagination = useSetAtom(currentPaginationAtom);
  const [prevPage, nextPage] = useAtomValue(paginationFamily(userId));

  const appSessions = unwrap(result);
  if (!appSessions) return <>Failed to load app sessions</>;

  const paginate = (pagination: Pagination): void => {
    startTransition(() => {
      setPagination(pagination);
    });
  };

  return (
    <BlockList>
      <H6>Apps</H6>
      <Text>{`${appSessions.totalCount} active sessions`}</Text>
      <PaginationControls
        onPrev={prevPage ? (): void => paginate(prevPage) : null}
        onNext={nextPage ? (): void => paginate(nextPage) : null}
        count={appSessions.totalCount}
        disabled={pending}
      />
    </BlockList>
  );
};

export default AppSessionsList;
