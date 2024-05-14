// Copyright 2023, 2024 The Matrix.org Foundation C.I.C.
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

import { useTransition } from "react";
import { useQuery } from "urql";

import { FragmentType, graphql, useFragment } from "../../gql";
import {
  FIRST_PAGE,
  Pagination,
  usePages,
  usePagination,
} from "../../pagination";
import PaginationControls from "../PaginationControls";
import UserEmail from "../UserEmail";

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

const FRAGMENT = graphql(/* GraphQL */ `
  fragment UserEmailList_user on User {
    id
    primaryEmail {
      id
    }
  }
`);

const CONFIG_FRAGMENT = graphql(/* GraphQL */ `
  fragment UserEmailList_siteConfig on SiteConfig {
    id
    ...UserEmail_siteConfig
  }
`);

const UserEmailList: React.FC<{
  user: FragmentType<typeof FRAGMENT>;
  siteConfig: FragmentType<typeof CONFIG_FRAGMENT>;
}> = ({ user, siteConfig }) => {
  const data = useFragment(FRAGMENT, user);
  const config = useFragment(CONFIG_FRAGMENT, siteConfig);
  const [pending, startTransition] = useTransition();

  const [pagination, setPagination] = usePagination();
  const [result, refreshList] = useQuery({
    query: QUERY,
    variables: { userId: data.id, ...pagination },
  });
  if (result.error) throw result.error;
  const emails = result.data?.user?.emails;
  if (!emails) throw new Error(); // Suspense mode is enabled

  const [prevPage, nextPage] = usePages(pagination, emails.pageInfo);

  const primaryEmailId = data.primaryEmail?.id;

  const paginate = (pagination: Pagination): void => {
    startTransition(() => {
      setPagination(pagination);
    });
  };

  // When removing an email, we want to refresh the list and go back to the first page
  const onRemove = (): void => {
    startTransition(() => {
      setPagination(FIRST_PAGE);
      refreshList();
    });
  };

  return (
    <>
      {emails.edges.map((edge) =>
        primaryEmailId === edge.node.id ? null : (
          <UserEmail
            email={edge.node}
            key={edge.cursor}
            siteConfig={config}
            onRemove={onRemove}
          />
        ),
      )}

      <PaginationControls
        autoHide
        count={emails.totalCount ?? 0}
        onPrev={prevPage ? (): void => paginate(prevPage) : null}
        onNext={nextPage ? (): void => paginate(nextPage) : null}
        disabled={pending}
      />
    </>
  );
};

export default UserEmailList;
