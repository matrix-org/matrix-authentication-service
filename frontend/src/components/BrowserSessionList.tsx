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

import { atom, useAtomValue, useSetAtom } from "jotai";
import { atomFamily } from "jotai/utils";
import { atomWithQuery } from "jotai-urql";
import { useTransition } from "react";

import { currentBrowserSessionIdAtom, mapQueryAtom } from "../atoms";
import { graphql } from "../gql";
import { PageInfo } from "../gql/graphql";
import {
  atomForCurrentPagination,
  atomWithPagination,
  Pagination,
} from "../pagination";
import { isErr, isOk, unwrapErr, unwrapOk } from "../result";

import BlockList from "./BlockList";
import BrowserSession from "./BrowserSession";
import GraphQLError from "./GraphQLError";
import PaginationControls from "./PaginationControls";
import { Title } from "./Typography";

const QUERY = graphql(/* GraphQL */ `
  query BrowserSessionList(
    $userId: ID!
    $first: Int
    $after: String
    $last: Int
    $before: String
  ) {
    user(id: $userId) {
      id
      browserSessions(
        first: $first
        after: $after
        last: $last
        before: $before
        state: ACTIVE
      ) {
        totalCount

        edges {
          cursor
          node {
            id
            ...BrowserSession_session
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

const currentPaginationAtom = atomForCurrentPagination();

const browserSessionListFamily = atomFamily((userId: string) => {
  const browserSessionListQuery = atomWithQuery({
    query: QUERY,
    getVariables: (get) => ({ userId, ...get(currentPaginationAtom) }),
  });

  const browserSessionList = mapQueryAtom(
    browserSessionListQuery,
    (data) => data.user?.browserSessions || null
  );

  return browserSessionList;
});

const pageInfoFamily = atomFamily((userId: string) => {
  const pageInfoAtom = atom(async (get): Promise<PageInfo | null> => {
    const result = await get(browserSessionListFamily(userId));
    return (isOk(result) && unwrapOk(result)?.pageInfo) || null;
  });
  return pageInfoAtom;
});

const paginationFamily = atomFamily((userId: string) => {
  const paginationAtom = atomWithPagination(
    currentPaginationAtom,
    pageInfoFamily(userId)
  );

  return paginationAtom;
});

const BrowserSessionList: React.FC<{ userId: string }> = ({ userId }) => {
  const currentSessionIdResult = useAtomValue(currentBrowserSessionIdAtom);
  const [pending, startTransition] = useTransition();
  const result = useAtomValue(browserSessionListFamily(userId));
  const setPagination = useSetAtom(currentPaginationAtom);
  const [prevPage, nextPage] = useAtomValue(paginationFamily(userId));

  if (isErr(currentSessionIdResult))
    return <GraphQLError error={unwrapErr(currentSessionIdResult)} />;
  if (isErr(result)) return <GraphQLError error={unwrapErr(result)} />;

  const browserSessions = unwrapOk(result);
  if (browserSessions === null) return <>Failed to load browser sessions</>;
  const currentSessionId = unwrapOk(currentSessionIdResult);

  const paginate = (pagination: Pagination): void => {
    startTransition(() => {
      setPagination(pagination);
    });
  };

  return (
    <BlockList>
      <Title>List of browser sessions:</Title>
      <PaginationControls
        onPrev={prevPage ? (): void => paginate(prevPage) : null}
        onNext={nextPage ? (): void => paginate(nextPage) : null}
        count={browserSessions.totalCount}
        disabled={pending}
      />
      {browserSessions.edges.map((n) => (
        <BrowserSession
          key={n.cursor}
          session={n.node}
          isCurrent={n.node.id === currentSessionId}
        />
      ))}
    </BlockList>
  );
};

export default BrowserSessionList;
