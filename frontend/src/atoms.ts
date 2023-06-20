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

import { AnyVariables, CombinedError, OperationContext } from "@urql/core";
import { atom, WritableAtom } from "jotai";
import { useHydrateAtoms } from "jotai/utils";
import { AtomWithQuery, atomWithQuery, clientAtom } from "jotai-urql";
import type { ReactElement } from "react";

import { graphql } from "./gql";
import { client } from "./graphql";
import { err, ok, Result } from "./result";

export type GqlResult<T> = Result<T, CombinedError>;
export type GqlAtom<T> = WritableAtom<
  Promise<GqlResult<T>>,
  [context?: Partial<OperationContext>],
  void
>;

/**
 * Map the result of a query atom to a new value, making it a GqlResult
 *
 * @param queryAtom: An atom got from atomWithQuery
 * @param mapper: A function that takes the data from the query and returns a new value
 */
export const mapQueryAtom = <Data, Variables extends AnyVariables, NewData>(
  queryAtom: AtomWithQuery<Data, Variables>,
  mapper: (data: Data) => NewData
): GqlAtom<NewData> => {
  return atom(
    async (get): Promise<GqlResult<NewData>> => {
      const result = await get(queryAtom);
      if (result.error) {
        return err(result.error);
      }

      if (result.data === undefined) {
        throw new Error("Query result is undefined");
      }

      return ok(mapper(result.data));
    },

    (_get, set, context) => {
      set(queryAtom, context);
    }
  );
};

export const HydrateAtoms: React.FC<{ children: ReactElement }> = ({
  children,
}) => {
  useHydrateAtoms([[clientAtom, client]]);
  return children;
};

const CURRENT_VIEWER_QUERY = graphql(/* GraphQL */ `
  query CurrentViewerQuery {
    viewer {
      __typename
      ... on User {
        id
      }

      ... on Anonymous {
        id
      }
    }
  }
`);

const currentViewerAtom = atomWithQuery({ query: CURRENT_VIEWER_QUERY });

export const currentUserIdAtom: GqlAtom<string | null> = mapQueryAtom(
  currentViewerAtom,
  (data) => {
    if (data.viewer.__typename === "User") {
      return data.viewer.id;
    }
    return null;
  }
);

const CURRENT_VIEWER_SESSION_QUERY = graphql(/* GraphQL */ `
  query CurrentViewerSessionQuery {
    viewerSession {
      __typename
      ... on BrowserSession {
        id
      }

      ... on Anonymous {
        id
      }
    }
  }
`);

const currentViewerSessionAtom = atomWithQuery({
  query: CURRENT_VIEWER_SESSION_QUERY,
});

export const currentBrowserSessionIdAtom: GqlAtom<string | null> = mapQueryAtom(
  currentViewerSessionAtom,
  (data) => {
    if (data.viewerSession.__typename === "BrowserSession") {
      return data.viewerSession.id;
    }
    return null;
  }
);
