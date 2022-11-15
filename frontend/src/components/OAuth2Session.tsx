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

import type { OAuth2Session_session$key } from "./__generated__/OAuth2Session_session.graphql";
import { graphql, useFragment } from "react-relay";
import Typography, { Bold, Code } from "./Typography";

type Props = {
  session: OAuth2Session_session$key;
};

const OAuth2Session: React.FC<Props> = ({ session }) => {
  const data = useFragment(
    graphql`
      fragment OAuth2Session_session on Oauth2Session {
        id
        scope
        client {
          id
          clientId
          clientName
          clientUri
        }
      }
    `,
    session
  );

  return (
    <div className="p-2 my-1 bg-grey-50 dark:bg-grey-450 dark:text-white rounded">
      <div>
        <Typography variant="body">
          Client ID: <Code>{data.scope}</Code>
        </Typography>
      </div>
      {data.client.clientName && (
        <Typography variant="body">
          Client name: <Bold>{data.client.clientName}</Bold>
        </Typography>
      )}
      <Typography variant="body">
        Scope: <Code>{data.scope}</Code>
      </Typography>
    </div>
  );
};

export default OAuth2Session;
