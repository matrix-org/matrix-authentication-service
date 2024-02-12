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

import { useState } from "react";

import { PageInfo } from "./gql/graphql";

export const FIRST_PAGE = Symbol("FIRST_PAGE");
export const LAST_PAGE = Symbol("LAST_PAGE");

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
  pagination: Pagination,
): pagination is ForwardPagination => {
  return Object.hasOwn(pagination, "first");
};

// Check if the pagination is backward pagination.
export const isBackwardPagination = (
  pagination: Pagination,
): pagination is BackwardPagination => {
  return Object.hasOwn(pagination, "last");
};

type Action = typeof FIRST_PAGE | typeof LAST_PAGE | Pagination;

// Hook to handle pagination state.
export const usePagination = (
  pageSize = 6,
): [Pagination, (action: Action) => void] => {
  const [pagination, setPagination] = useState<Pagination>({
    first: pageSize,
    after: null,
  });

  const handlePagination = (action: Action): void => {
    if (action === FIRST_PAGE) {
      setPagination({
        first: pageSize,
        after: null,
      });
    } else if (action === LAST_PAGE) {
      setPagination({
        last: pageSize,
        before: null,
      });
    } else {
      setPagination(action);
    }
  };

  return [pagination, handlePagination];
};

// Compute the previous and next pagination based on the current pagination and the page info.
export const usePages = (
  currentPagination: Pagination,
  pageInfo: PageInfo | null,
  pageSize = 6,
): [BackwardPagination | null, ForwardPagination | null] => {
  const hasProbablyPreviousPage =
    isForwardPagination(currentPagination) && currentPagination.after !== null;
  const hasProbablyNextPage =
    isBackwardPagination(currentPagination) &&
    currentPagination.before !== null;

  let previousPagination: BackwardPagination | null = null;
  let nextPagination: ForwardPagination | null = null;
  if (pageInfo?.hasPreviousPage || hasProbablyPreviousPage) {
    previousPagination = {
      last: pageSize,
      before: pageInfo?.startCursor ?? null,
    };
  }

  if (pageInfo?.hasNextPage || hasProbablyNextPage) {
    nextPagination = {
      first: pageSize,
      after: pageInfo?.endCursor ?? null,
    };
  }

  return [previousPagination, nextPagination];
};
