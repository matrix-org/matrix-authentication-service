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

import { atomWithQuery } from "jotai-urql";
import { atom, useSetAtom, useAtomValue } from "jotai";
import { atomFamily, atomWithDefault } from "jotai/utils";
import { useTransition } from "react";

import BlockList from "./BlockList";
import CompatSsoLogin from "./CompatSsoLogin";
import { Title } from "./Typography";
import { graphql } from "../gql";
import { atomWithPagination, pageSizeAtom, Pagination } from "../pagination";
import { PageInfo } from "../gql/graphql";
import PaginationControls from "./PaginationControls";

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
      }
    }
  }
`);

const currentPagination = atomWithDefault<Pagination>((get) => ({
  first: get(pageSizeAtom),
  after: null,
}));

const compatSsoLoginListFamily = atomFamily((userId: string) => {
  const compatSsoLoginList = atomWithQuery({
    query: QUERY,
    getVariables: (get) => ({ userId, ...get(currentPagination) }),
  });

  return compatSsoLoginList;
});

const pageInfoFamily = atomFamily((userId: string) => {
  const pageInfoAtom = atom(async (get): Promise<PageInfo | null> => {
    const result = await get(compatSsoLoginListFamily(userId));
    return result.data?.user?.oauth2Sessions?.pageInfo ?? null;
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

const CompatSsoLoginList: React.FC<{ userId: string }> = ({ userId }) => {
  const [pending, startTransition] = useTransition();
  const result = useAtomValue(compatSsoLoginListFamily(userId));
  const setPagination = useSetAtom(currentPagination);
  const [prevPage, nextPage] = useAtomValue(paginationFamily(userId));

  const paginate = (pagination: Pagination) => {
    startTransition(() => {
      setPagination(pagination);
    });
  };

  if (result.data?.user?.compatSsoLogins) {
    const data = result.data.user.compatSsoLogins;
    return (
      <BlockList>
        <Title>List of compatibility sessions:</Title>
        <PaginationControls
          onPrev={prevPage ? () => paginate(prevPage) : null}
          onNext={nextPage ? () => paginate(nextPage) : null}
          disabled={pending}
        />
        {data.edges.map((n) => (
          <CompatSsoLogin login={n.node} key={n.node.id} />
        ))}
      </BlockList>
    );
  }

  return <>Failed to load list of compatibility sessions.</>;
};

export default CompatSsoLoginList;
