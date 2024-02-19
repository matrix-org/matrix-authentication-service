// Copyright 2024 The Matrix.org Foundation C.I.C.
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

import { createFileRoute, notFound } from "@tanstack/react-router";
import { H5 } from "@vector-im/compound-web";
import { useTranslation } from "react-i18next";
import { useQuery } from "urql";

import BlockList from "../components/BlockList";
import BrowserSession from "../components/BrowserSession";
import { ButtonLink } from "../components/ButtonLink";
import { graphql } from "../gql";
import {
  Pagination,
  isForwardPagination,
  paginationSchema,
  usePages,
} from "../pagination";

const PAGE_SIZE = 6;

const QUERY = graphql(/* GraphQL */ `
  query BrowserSessionList(
    $first: Int
    $after: String
    $last: Int
    $before: String
  ) {
    viewerSession {
      __typename
      ... on BrowserSession {
        id

        user {
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
    }
  }
`);

export const Route = createFileRoute("/_account/sessions/browsers")({
  // We paginate backwards, so we need to validate the `last` parameter by default
  validateSearch: paginationSchema.catch({ last: PAGE_SIZE }),

  loaderDeps: ({ search }): Pagination =>
    isForwardPagination(search)
      ? { first: search.first, after: search.after }
      : { last: search.last, before: search.before },

  async loader({ context, deps: pagination, abortController: { signal } }) {
    const result = await context.client.query(QUERY, pagination, {
      fetchOptions: { signal },
    });
    if (result.error) throw result.error;
    if (result.data?.viewerSession?.__typename !== "BrowserSession")
      throw notFound();
  },

  component: BrowserSessions,
});

function BrowserSessions(): React.ReactElement {
  const { t } = useTranslation();
  const pagination = Route.useLoaderDeps();
  const [list] = useQuery({ query: QUERY, variables: pagination });
  if (list.error) throw list.error;
  const currentSession =
    list.data?.viewerSession.__typename === "BrowserSession"
      ? list.data.viewerSession
      : null;
  if (currentSession === null) throw notFound();

  const [backwardPage, forwardPage] = usePages(
    pagination,
    currentSession.user.browserSessions.pageInfo,
    PAGE_SIZE,
  );

  // We reverse the list as we are paginating backwards
  const edges = [...currentSession.user.browserSessions.edges].reverse();
  return (
    <BlockList>
      <H5>{t("frontend.browser_sessions_overview.heading")}</H5>

      {edges.map((n) => (
        <BrowserSession
          key={n.cursor}
          session={n.node}
          isCurrent={currentSession.id === n.node.id}
        />
      ))}

      <div className="flex *:flex-1">
        <ButtonLink
          kind="secondary"
          size="sm"
          disabled={!forwardPage}
          to={Route.fullPath}
          search={forwardPage}
        >
          {t("common.previous")}
        </ButtonLink>

        {/* Spacer */}
        <div />

        <ButtonLink
          kind="secondary"
          size="sm"
          disabled={!backwardPage}
          to={Route.fullPath}
          search={backwardPage}
        >
          {t("common.next")}
        </ButtonLink>
      </div>
    </BlockList>
  );
}
