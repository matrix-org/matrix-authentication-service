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
import { H3, H5 } from "@vector-im/compound-web";
import { useTranslation } from "react-i18next";
import { useQuery } from "urql";

import BlockList from "../components/BlockList";
import { ButtonLink } from "../components/ButtonLink";
import CompatSession from "../components/CompatSession";
import OAuth2Session from "../components/OAuth2Session";
import BrowserSessionsOverview from "../components/UserSessionsOverview/BrowserSessionsOverview";
import { graphql } from "../gql";
import {
  Pagination,
  isForwardPagination,
  paginationSchema,
  usePages,
} from "../pagination";

const PAGE_SIZE = 6;

const QUERY = graphql(/* GraphQL */ `
  query SessionsOverviewQuery {
    viewer {
      __typename

      ... on User {
        id
        ...BrowserSessionsOverview_user
      }
    }
  }
`);

const LIST_QUERY = graphql(/* GraphQL */ `
  query AppSessionsListQuery(
    $before: String
    $after: String
    $first: Int
    $last: Int
  ) {
    viewer {
      __typename

      ... on User {
        id
        appSessions(
          before: $before
          after: $after
          first: $first
          last: $last
          state: ACTIVE
        ) {
          edges {
            cursor
            node {
              __typename
              ...CompatSession_session
              ...OAuth2Session_session
            }
          }

          totalCount
          pageInfo {
            startCursor
            endCursor
            hasNextPage
            hasPreviousPage
          }
        }
      }
    }
  }
`);

// A type-safe way to ensure we've handled all session types
const unknownSessionType = (type: never): never => {
  throw new Error(`Unknown session type: ${type}`);
};

export const Route = createFileRoute("/_account/sessions/")({
  // We paginate backwards, so we need to validate the `last` parameter by default
  validateSearch: paginationSchema.catch({ last: PAGE_SIZE }),

  loaderDeps: ({ search }): Pagination =>
    isForwardPagination(search)
      ? { first: search.first, after: search.after }
      : { last: search.last, before: search.before },

  async loader({ context, deps: pagination, abortController: { signal } }) {
    const [overview, list] = await Promise.all([
      context.client.query(QUERY, {}, { fetchOptions: { signal } }),
      context.client.query(LIST_QUERY, pagination, {
        fetchOptions: { signal },
      }),
    ]);

    if (overview.error) throw overview.error;
    if (list.error) throw list.error;
    if (overview.data?.viewer?.__typename !== "User") throw notFound();
    if (list.data?.viewer?.__typename !== "User") throw notFound();
  },

  component: Sessions,
});

function Sessions(): React.ReactElement {
  const { t } = useTranslation();
  const pagination = Route.useLoaderDeps();
  const [overview] = useQuery({ query: QUERY });
  if (overview.error) throw overview.error;
  const user =
    overview.data?.viewer.__typename === "User" ? overview.data.viewer : null;
  if (user === null) throw notFound();

  const [list] = useQuery({ query: LIST_QUERY, variables: pagination });
  if (list.error) throw list.error;
  const appSessions =
    list.data?.viewer.__typename === "User"
      ? list.data.viewer.appSessions
      : null;
  if (appSessions === null) throw notFound();

  const [backwardPage, forwardPage] = usePages(
    pagination,
    appSessions.pageInfo,
    PAGE_SIZE,
  );

  // We reverse the list as we are paginating backwards
  const edges = [...appSessions.edges].reverse();

  return (
    <BlockList>
      <H3>{t("frontend.user_sessions_overview.heading")}</H3>
      <BrowserSessionsOverview user={user} />

      <H5>
        {t("frontend.user_sessions_overview.active_sessions", {
          count: appSessions.totalCount,
        })}
      </H5>

      {edges.map((session) => {
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
