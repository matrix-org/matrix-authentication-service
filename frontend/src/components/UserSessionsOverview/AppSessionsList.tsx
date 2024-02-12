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

import { H5 } from "@vector-im/compound-web";
import { useTransition } from "react";
import { useTranslation } from "react-i18next";
import { useQuery } from "urql";

import { graphql } from "../../gql";
import { Pagination, usePages, usePagination } from "../../pagination";
import BlockList from "../BlockList";
import CompatSession from "../CompatSession";
import OAuth2Session from "../OAuth2Session";
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
            __typename
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

// A type-safe way to ensure we've handled all session types
const unknownSessionType = (type: never): never => {
  throw new Error(`Unknown session type: ${type}`);
};

const AppSessionsList: React.FC<{ userId: string }> = ({ userId }) => {
  const [pending, startTransition] = useTransition();
  const [pagination, setPagination] = usePagination();
  const [result] = useQuery({
    query: QUERY,
    variables: { userId, ...pagination },
  });
  if (result.error) throw result.error;
  const appSessions = result.data?.user?.appSessions;
  if (!appSessions) throw new Error(); // Suspense mode is enabled
  const [prevPage, nextPage] = usePages(pagination, appSessions.pageInfo);
  const { t } = useTranslation();

  const paginate = (pagination: Pagination): void => {
    startTransition(() => {
      setPagination(pagination);
    });
  };

  return (
    <BlockList>
      <header>
        <H5>{t("frontend.app_sessions_list.heading")}</H5>
      </header>
      {appSessions.edges.map((session) => {
        const type = session.node.__typename;
        switch (type) {
          case "Oauth2Session":
            return (
              <OAuth2Session key={session.cursor} session={session.node} />
            );
          case "CompatSession":
            return (
              <CompatSession key={session.cursor} session={session.node} />
            );
          default:
            unknownSessionType(type);
        }
      })}
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
