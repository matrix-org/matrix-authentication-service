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

import { Body, Bold, Code } from "./Typography";
import Block from "./Block";
import { Link } from "../Router";
import { FragmentType, graphql, useFragment } from "../gql";

const FRAGMENT = graphql(/* GraphQL */ `
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
`);

type Props = {
  session: FragmentType<typeof FRAGMENT>;
};

const OAuth2Session: React.FC<Props> = ({ session }) => {
  const data = useFragment(FRAGMENT, session);

  return (
    <Block>
      <Body>
        <Link
          route={{ type: "client", id: data.client.id }}
          className="text-links hover:text-links/75"
        >
          Client ID: <Code>{data.client.clientId}</Code>
        </Link>
      </Body>
      {data.client.clientName && (
        <Body>
          Client name: <Bold>{data.client.clientName}</Bold>
        </Body>
      )}
      <Body>
        Scope: <Code>{data.scope}</Code>
      </Body>
    </Block>
  );
};

export default OAuth2Session;
