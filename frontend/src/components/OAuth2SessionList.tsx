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

import { useAtomValue, atom, useSetAtom } from "jotai";
import { atomFamily } from "jotai/utils";
import { atomWithQuery } from "jotai-urql";
import { useTransition } from "react";

import { graphql } from "../gql";
import { PageInfo } from "../gql/graphql";
import {
  atomForCurrentPagination,
  atomWithPagination,
  Pagination,
} from "../pagination";

import BlockList from "./BlockList";
import OAuth2Session from "./OAuth2Session";
import PaginationControls from "./PaginationControls";
import { Title } from "./Typography";

const QUERY = graphql(/* GraphQL */ `
  query OAuth2SessionListQuery(
    $userId: ID!
    $first: Int
    $after: String
    $last: Int
    $before: String
  ) {
    user(id: $userId) {
      id
      oauth2Sessions(
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

const oauth2SessionListFamily = atomFamily((userId: string) => {
  const oauth2SessionList = atomWithQuery({
    query: QUERY,
    getVariables: (get) => ({ userId, ...get(currentPaginationAtom) }),
  });

  return oauth2SessionList;
});

const pageInfoFamily = atomFamily((userId: string) => {
  const pageInfoAtom = atom(async (get): Promise<PageInfo | null> => {
    const result = await get(oauth2SessionListFamily(userId));
    return result.data?.user?.oauth2Sessions?.pageInfo ?? null;
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

type Props = {
  userId: string;
};

const OAuth2SessionList: React.FC<Props> = ({ userId }) => {
  const [pending, startTransition] = useTransition();
  const result = useAtomValue(oauth2SessionListFamily(userId));
  const setPagination = useSetAtom(currentPaginationAtom);
  const [prevPage, nextPage] = useAtomValue(paginationFamily(userId));

  const paginate = (pagination: Pagination) => {
    startTransition(() => {
      setPagination(pagination);
    });
  };

  if (result.data?.user?.oauth2Sessions) {
    const data = result.data.user.oauth2Sessions;
    return (
      <BlockList>
        <Title>List of OAuth 2.0 sessions:</Title>
        <PaginationControls
          onPrev={prevPage ? () => paginate(prevPage) : null}
          onNext={nextPage ? () => paginate(nextPage) : null}
          disabled={pending}
        />
        {data.edges.map((n) => (
          <OAuth2Session key={n.cursor} session={n.node} />
        ))}
      </BlockList>
    );
  } else {
    return <>Failed to load OAuth 2.0 session list</>;
  }
};

export default OAuth2SessionList;
