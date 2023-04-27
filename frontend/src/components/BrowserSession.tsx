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

import { Link } from "../Router";
import { FragmentType, graphql, useFragment } from "../gql";

import Block from "./Block";
import DateTime from "./DateTime";
import { Body, Subtitle } from "./Typography";

const FRAGMENT = graphql(/* GraphQL */ `
  fragment BrowserSession_session on BrowserSession {
    id
    createdAt
    lastAuthentication {
      id
      createdAt
    }
  }
`);

type Props = {
  session: FragmentType<typeof FRAGMENT>;
  isCurrent: boolean;
};

const BrowserSession: React.FC<Props> = ({ session, isCurrent }) => {
  const data = useFragment(FRAGMENT, session);

  const lastAuthentication = data.lastAuthentication?.createdAt;
  const createdAt = data.createdAt;

  return (
    <Block>
      {isCurrent && <Subtitle>Current session</Subtitle>}
      <Body>
        <Link
          route={{ type: "session", id: data.id }}
          className="text-links hover:text-links/75"
        >
          Started: <DateTime datetime={createdAt} />
        </Link>
      </Body>
      <Body>
        Last authentication:{" "}
        {lastAuthentication ? (
          <DateTime datetime={lastAuthentication} />
        ) : (
          "never"
        )}
      </Body>
    </Block>
  );
};

export default BrowserSession;
