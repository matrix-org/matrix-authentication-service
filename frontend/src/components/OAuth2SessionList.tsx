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

import { atom, useAtom, useAtomValue, useSetAtom } from "jotai";
import { atomFamily } from "jotai/utils";
import { atomWithQuery } from "jotai-urql";
import { useTransition } from "react";

import { mapQueryAtom } from "../atoms";
import { graphql } from "../gql";
import { Oauth2SessionState, PageInfo } from "../gql/graphql";
import {
  atomForCurrentPagination,
  atomWithPagination,
  FIRST_PAGE,
  Pagination,
} from "../pagination";
import { isErr, isOk, unwrapErr, unwrapOk } from "../result";

import BlockList from "./BlockList";
import GraphQLError from "./GraphQLError";
import OAuth2Session from "./OAuth2Session";
import PaginationControls from "./PaginationControls";
import { Title } from "./Typography";

const QUERY = graphql(/* GraphQL */ `
  query OAuth2SessionListQuery(
    $userId: ID!
    $state: Oauth2SessionState
    $first: Int
    $after: String
    $last: Int
    $before: String
  ) {
    user(id: $userId) {
      id
      oauth2Sessions(
        state: $state
        first: $first
        after: $after
        last: $last
        before: $before
      ) {
        edges {
          cursor
          node {
            id
            ...OAuth2Session_session
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

const currentPaginationAtom = atomForCurrentPagination();
const filterAtom = atom<Oauth2SessionState | null>(Oauth2SessionState.Active);

const oauth2SessionListFamily = atomFamily((userId: string) => {
  const oauth2SessionListQuery = atomWithQuery({
    query: QUERY,
    getVariables: (get) => ({
      userId,
      state: get(filterAtom),
      ...get(currentPaginationAtom),
    }),
  });

  const oauth2SessionList = mapQueryAtom(
    oauth2SessionListQuery,
    (data) => data.user?.oauth2Sessions || null,
  );

  return oauth2SessionList;
});

const pageInfoFamily = atomFamily((userId: string) => {
  const pageInfoAtom = atom(async (get): Promise<PageInfo | null> => {
    const result = await get(oauth2SessionListFamily(userId));
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

type Props = {
  userId: string;
};

const OAuth2SessionList: React.FC<Props> = ({ userId }) => {
  const [pending, startTransition] = useTransition();
  const result = useAtomValue(oauth2SessionListFamily(userId));
  const setPagination = useSetAtom(currentPaginationAtom);
  const [prevPage, nextPage] = useAtomValue(paginationFamily(userId));
  const [filter, setFilter] = useAtom(filterAtom);

  if (isErr(result)) return <GraphQLError error={unwrapErr(result)} />;
  const oauth2Sessions = unwrapOk(result);
  if (oauth2Sessions === null) return <>Failed to load sessions.</>;

  const paginate = (pagination: Pagination): void => {
    startTransition(() => {
      setPagination(pagination);
    });
  };

  const toggleFilter = (): void => {
    startTransition(() => {
      setPagination(FIRST_PAGE);
      setFilter(
        filter === Oauth2SessionState.Active ? null : Oauth2SessionState.Active,
      );
    });
  };

  return (
    <BlockList>
      <Title>New apps:</Title>
      <label>
        <input
          type="checkbox"
          checked={filter === Oauth2SessionState.Active}
          onChange={toggleFilter}
        />{" "}
        Active only
      </label>
      <PaginationControls
        onPrev={prevPage ? (): void => paginate(prevPage) : null}
        onNext={nextPage ? (): void => paginate(nextPage) : null}
        count={oauth2Sessions.totalCount}
        disabled={pending}
      />
      {oauth2Sessions.edges.map((n) => (
        <OAuth2Session key={n.cursor} session={n.node} />
      ))}
    </BlockList>
  );
};

export default OAuth2SessionList;
