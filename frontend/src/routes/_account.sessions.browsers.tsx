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
  type Pagination,
  type BackwardPagination,
  paginationSchema,
} from "../pagination";

const PAGE_SIZE = 6;
const DEFAULT_PAGE: BackwardPagination = { last: PAGE_SIZE };

export const QUERY = graphql(/* GraphQL */ `
  query BrowserSessionList(
    $first: Int
    $after: String
    $last: Int
    $before: String
    $lastActive: DateFilter
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
            lastActive: $lastActive
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

export const Route = createFileRoute("/_account/sessions/browsers")({
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

    const result = await context.client.query(QUERY, variables, {
      fetchOptions: { signal },
    });
    if (result.error) throw result.error;
    if (result.data?.viewerSession?.__typename !== "BrowserSession")
      throw notFound();
  },

  component: () => <div>Hello /_account/sessions/browsers!</div>,
});
