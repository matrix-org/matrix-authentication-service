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

import { useQuery } from "urql";

import { graphql } from "../../gql";

const CURRENT_VIEWER_SESSION_QUERY = graphql(/* GraphQL */ `
  query CurrentViewerSessionQuery {
    viewerSession {
      __typename
      ... on BrowserSession {
        id
      }
    }
  }
`);

/**
 * Query the current browser session id
 * and unwrap the result
 * throws error when error result
 */
export const useCurrentBrowserSessionId = (): string | null => {
  const [result] = useQuery({ query: CURRENT_VIEWER_SESSION_QUERY });
  if (result.error) throw result.error;
  if (!result.data) throw new Error(); // Suspense mode is enabled
  return result.data.viewer.__typename === "User"
    ? result.data.viewer.id
    : null;
};
