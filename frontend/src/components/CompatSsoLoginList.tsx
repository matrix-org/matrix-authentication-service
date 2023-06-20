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

import { atom, useSetAtom, useAtomValue } from "jotai";
import { atomFamily } from "jotai/utils";
import { atomWithQuery } from "jotai-urql";
import { useTransition } from "react";

import { mapQueryAtom } from "../atoms";
import { graphql } from "../gql";
import { PageInfo } from "../gql/graphql";
import {
  atomForCurrentPagination,
  atomWithPagination,
  Pagination,
} from "../pagination";
import { isErr, isOk, unwrapErr, unwrapOk } from "../result";

import BlockList from "./BlockList";
import CompatSsoLogin from "./CompatSsoLogin";
import GraphQLError from "./GraphQLError";
import PaginationControls from "./PaginationControls";
import { Title } from "./Typography";

const QUERY = graphql(/* GraphQL */ `
  query CompatSsoLoginList(
    $userId: ID!
    $first: Int
    $after: String
    $last: Int
    $before: String
  ) {
    user(id: $userId) {
      id
      compatSsoLogins(
        first: $first
        after: $after
        last: $last
        before: $before
      ) {
        edges {
          node {
            id
            ...CompatSsoLogin_login
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

const compatSsoLoginListFamily = atomFamily((userId: string) => {
  const compatSsoLoginListQuery = atomWithQuery({
    query: QUERY,
    getVariables: (get) => ({ userId, ...get(currentPaginationAtom) }),
  });

  const compatSsoLoginList = mapQueryAtom(
    compatSsoLoginListQuery,
    (data) => data.user?.compatSsoLogins || null
  );

  return compatSsoLoginList;
});

const pageInfoFamily = atomFamily((userId: string) => {
  const pageInfoAtom = atom(async (get): Promise<PageInfo | null> => {
    const result = await get(compatSsoLoginListFamily(userId));
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

const CompatSsoLoginList: React.FC<{ userId: string }> = ({ userId }) => {
  const [pending, startTransition] = useTransition();
  const result = useAtomValue(compatSsoLoginListFamily(userId));
  const setPagination = useSetAtom(currentPaginationAtom);
  const [prevPage, nextPage] = useAtomValue(paginationFamily(userId));

  if (isErr(result)) return <GraphQLError error={unwrapErr(result)} />;
  const compatSsoLoginList = unwrapOk(result);
  if (compatSsoLoginList === null)
    return <>Failed to load list of compatibility sessions.</>;

  const paginate = (pagination: Pagination): void => {
    startTransition(() => {
      setPagination(pagination);
    });
  };

  return (
    <BlockList>
      <Title>List of compatibility sessions:</Title>
      <PaginationControls
        onPrev={prevPage ? (): void => paginate(prevPage) : null}
        onNext={nextPage ? (): void => paginate(nextPage) : null}
        disabled={pending}
      />
      {compatSsoLoginList.edges.map((n) => (
        <CompatSsoLogin login={n.node} key={n.node.id} />
      ))}
    </BlockList>
  );
};

export default CompatSsoLoginList;
