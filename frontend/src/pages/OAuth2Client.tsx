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

import { graphql, useLazyLoadQuery } from "react-relay";
import { useParams } from "react-router-dom";

import type { OAuth2ClientQuery } from "./__generated__/OAuth2ClientQuery.graphql";

const OAuth2Client: React.FC = () => {
  const { id } = useParams();
  if (!id) {
    throw new Error("Missing parameter");
  }

  const data = useLazyLoadQuery<OAuth2ClientQuery>(
    graphql`
      query OAuth2ClientQuery($id: ID!) {
        oauth2Client(id: $id) {
          id
          clientId
          clientName
          clientUri
          tosUri
          policyUri
          redirectUris
        }
      }
    `,
    { id }
  );

  return (
    <pre>
      <code>{JSON.stringify(data.oauth2Client, null, 2)}</code>
    </pre>
  );
};

export default OAuth2Client;
