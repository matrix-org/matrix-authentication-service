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

import { atom } from "jotai";
import { useHydrateAtoms } from "jotai/utils";
import { atomWithQuery, clientAtom } from "jotai-urql";
import type { ReactElement } from "react";

import { graphql } from "./gql";
import { client } from "./graphql";

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

export const currentUserIdAtom = atom(async (get) => {
  const result = await get(currentViewerAtom);
  if (result.data?.viewer.__typename === "User") {
    return result.data.viewer.id;
  }
  return null;
});

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

export const currentBrowserSessionIdAtom = atom(
  async (get): Promise<string | null> => {
    const result = await get(currentViewerSessionAtom);
    if (result.data?.viewerSession.__typename === "BrowserSession") {
      return result.data.viewerSession.id;
    }
    return null;
  }
);
