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

import { atom, Atom } from "jotai";

import { PageInfo } from "./gql/graphql";

export type ForwardPagination = {
  first: number;
  after: string | null;
};

export type BackwardPagination = {
  last: number;
  before: string | null;
};

export type Pagination = ForwardPagination | BackwardPagination;

// Check if the pagination is forward pagination.
export const isForwardPagination = (
  pagination: Pagination
): pagination is ForwardPagination => {
  return pagination.hasOwnProperty("first");
};

// Check if the pagination is backward pagination.
export const isBackwardPagination = (
  pagination: Pagination
): pagination is BackwardPagination => {
  return pagination.hasOwnProperty("last");
};

// This atom sets the default page size for pagination.
export const pageSizeAtom = atom(6);

// This atom is used to create a pagination atom that gives the previous and
// next pagination objects, given the current pagination and the page info.
export const atomWithPagination = (
  currentPaginationAtom: Atom<Pagination>,
  pageInfoAtom: Atom<Promise<PageInfo | null>>
): Atom<Promise<[BackwardPagination | null, ForwardPagination | null]>> => {
  const paginationAtom = atom(
    async (
      get
    ): Promise<[BackwardPagination | null, ForwardPagination | null]> => {
      const currentPagination = get(currentPaginationAtom);
      const pageInfo = await get(pageInfoAtom);
      const hasProbablyPreviousPage =
        isForwardPagination(currentPagination) &&
        currentPagination.after !== null;
      const hasProbablyNextPage =
        isBackwardPagination(currentPagination) &&
        currentPagination.before !== null;

      let previousPagination: BackwardPagination | null = null;
      let nextPagination: ForwardPagination | null = null;
      if (pageInfo?.hasPreviousPage || hasProbablyPreviousPage) {
        previousPagination = {
          last: get(pageSizeAtom),
          before: pageInfo?.startCursor ?? null,
        };
      }

      if (pageInfo?.hasNextPage || hasProbablyNextPage) {
        nextPagination = {
          first: get(pageSizeAtom),
          after: pageInfo?.endCursor ?? null,
        };
      }

      return [previousPagination, nextPagination];
    }
  );

  return paginationAtom;
};
