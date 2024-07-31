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
import * as z from "zod";

import { graphql } from "../gql";
import {
  type BackwardPagination,
  type Pagination,
  paginationSchema,
} from "../pagination";
import { getNinetyDaysAgo } from "../utils/dates";

const PAGE_SIZE = 6;
const DEFAULT_PAGE: BackwardPagination = { last: PAGE_SIZE };

export const QUERY = graphql(/* GraphQL */ `
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

export const LIST_QUERY = graphql(/* GraphQL */ `
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

const searchSchema = z.object({
  inactive: z.literal(true).optional().catch(undefined),
});

type Search = z.infer<typeof searchSchema>;

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
      lastActive: inactive ? { before: getNinetyDaysAgo() } : undefined,
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
});
