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
import { H3, Separator } from "@vector-im/compound-web";
import { useTranslation } from "react-i18next";
import { useQuery } from "urql";
import * as z from "zod";

import BlockList from "../components/BlockList";
import { ButtonLink } from "../components/ButtonLink";
import CompatSession from "../components/CompatSession";
import EmptyState from "../components/EmptyState";
import Filter from "../components/Filter";
import OAuth2Session from "../components/OAuth2Session";
import BrowserSessionsOverview from "../components/UserSessionsOverview/BrowserSessionsOverview";
import { graphql } from "../gql";
import {
  BackwardPagination,
  Pagination,
  paginationSchema,
  usePages,
} from "../pagination";

const PAGE_SIZE = 6;
const DEFAULT_PAGE: BackwardPagination = { last: PAGE_SIZE };

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
    $lastActive: DateFilter
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
          lastActive: $lastActive
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

const searchSchema = z.object({
  inactive: z.literal(true).optional().catch(undefined),
});

type Search = z.infer<typeof searchSchema>;

const getNintyDaysAgo = (): string => {
  const date = new Date(Date.now() - 90 * 24 * 60 * 60 * 1000);
  // Round down to the start of the day to avoid rerendering/requerying
  date.setHours(0, 0, 0, 0);
  return date.toISOString();
};

export const Route = createFileRoute("/_account/sessions/")({
  // We paginate backwards, so we need to validate the `last` parameter by default
  validateSearch: paginationSchema.catch(DEFAULT_PAGE).and(searchSchema),

  loaderDeps: ({ search }): Pagination & Search =>
    paginationSchema.and(searchSchema).parse(search),

  async loader({
    context,
    deps: { inactive, ...pagination },
    abortController: { signal },
  }) {
    const variables = {
      lastActive: inactive ? { before: getNintyDaysAgo() } : undefined,
      ...pagination,
    };

    const [overview, list] = await Promise.all([
      context.client.query(QUERY, {}, { fetchOptions: { signal } }),
      context.client.query(LIST_QUERY, variables, {
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
  const { inactive, ...pagination } = Route.useLoaderDeps();
  const [overview] = useQuery({ query: QUERY });
  if (overview.error) throw overview.error;
  const user =
    overview.data?.viewer.__typename === "User" ? overview.data.viewer : null;
  if (user === null) throw notFound();

  const variables = {
    lastActive: inactive ? { before: getNintyDaysAgo() } : undefined,
    ...pagination,
  };

  const [list] = useQuery({ query: LIST_QUERY, variables });
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
      <Separator />
      <div className="flex gap-2 justify-start items-center">
        <Filter
          to={Route.fullPath}
          enabled={inactive}
          search={{ ...DEFAULT_PAGE, inactive: inactive ? undefined : true }}
        >
          {t("frontend.last_active.inactive_90_days")}
        </Filter>
      </div>
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

      {appSessions.totalCount === 0 && (
        <EmptyState>
          {inactive
            ? t(
                "frontend.user_sessions_overview.no_active_sessions.inactive_90_days",
              )
            : t("frontend.user_sessions_overview.no_active_sessions.default")}
        </EmptyState>
      )}

      {/* Only show the pagination buttons if there are pages to go to */}
      {(forwardPage || backwardPage) && (
        <div className="flex *:flex-1">
          <ButtonLink
            kind="secondary"
            size="sm"
            disabled={!forwardPage}
            to={Route.fullPath}
            search={{ inactive, ...(forwardPage || pagination) }}
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
            search={{ inactive, ...(backwardPage || pagination) }}
          >
            {t("common.next")}
          </ButtonLink>
        </div>
      )}
    </BlockList>
  );
}
