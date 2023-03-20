// Copyright 2022 The Matrix.org Foundation C.I.C.
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

import { useAtomValue } from "jotai";
import { atomsWithQuery } from "jotai-urql";
import { useMemo } from "react";
import { graphql } from "../gql";

const QUERY = graphql(/* GraphQL */ `
  query BrowserSessionQuery($id: ID!) {
    browserSession(id: $id) {
      id
      createdAt
      lastAuthentication {
        id
        createdAt
      }
      user {
        id
        username
      }
    }
  }
`);

const BrowserSession: React.FC<{ id: string }> = ({ id }) => {
  const data = useAtomValue(
    useMemo(() => atomsWithQuery(QUERY, () => ({ id })), [id])[0]
  );

  return (
    <pre>
      <code>{JSON.stringify(data.browserSession, null, 2)}</code>
    </pre>
  );
};

export default BrowserSession;
