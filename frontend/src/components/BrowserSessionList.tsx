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

import { useState, useTransition } from "react";
import { useQuery } from "urql";

import { graphql } from "../gql";
import { SessionState } from "../gql/graphql";
import { FIRST_PAGE, Pagination, usePages, usePagination } from "../pagination";

import BlockList from "./BlockList";
import BrowserSession from "./BrowserSession";
import PaginationControls from "./PaginationControls";
import SessionListHeader from "./SessionList/SessionListHeader";

const QUERY = graphql(/* GraphQL */ `
  query BrowserSessionList(
    $userId: ID!
    $state: SessionState
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
        state: $state
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

const BrowserSessionList: React.FC<{ userId: string }> = ({ userId }) => {
  const [pagination, setPagination] = usePagination();
  const [pending, startTransition] = useTransition();
  const [filter, setFilter] = useState<SessionState | null>(
    SessionState.Active,
  );
  const [result] = useQuery({
    query: QUERY,
    variables: { userId, state: filter, ...pagination },
  });
  if (result.error) throw result.error;
  const browserSessions = result.data?.user?.browserSessions;
  if (!browserSessions) throw new Error(); // Suspense mode is enabled

  const [prevPage, nextPage] = usePages(pagination, browserSessions.pageInfo);

  if (browserSessions === null) return <>Failed to load browser sessions</>;

  const paginate = (pagination: Pagination): void => {
    startTransition(() => {
      setPagination(pagination);
    });
  };

  const toggleFilter = (): void => {
    startTransition(() => {
      setPagination(FIRST_PAGE);
      setFilter(filter === SessionState.Active ? null : SessionState.Active);
    });
  };

  return (
    <BlockList>
      <SessionListHeader title="Browsers" />
      <PaginationControls
        onPrev={prevPage ? (): void => paginate(prevPage) : null}
        onNext={nextPage ? (): void => paginate(nextPage) : null}
        count={browserSessions.totalCount}
        disabled={pending}
      />
      <label>
        <input
          type="checkbox"
          disabled={pending}
          checked={filter === SessionState.Active}
          onChange={toggleFilter}
        />{" "}
        Active only
      </label>
      {browserSessions.edges.map((n) => (
        <BrowserSession key={n.cursor} session={n.node} />
      ))}
    </BlockList>
  );
};

export default BrowserSessionList;
