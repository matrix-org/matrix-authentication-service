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

import type { BrowserSession_session$key } from "./__generated__/BrowserSession_session.graphql";
import { graphql, useFragment } from "react-relay";

import Block from "./Block";
import { Body, Subtitle } from "./Typography";
import DateTime from "./DateTime";

type Props = {
  session: BrowserSession_session$key;
  isCurrent: boolean;
};

const BrowserSession: React.FC<Props> = ({ session, isCurrent }) => {
  const data = useFragment(
    graphql`
      fragment BrowserSession_session on BrowserSession {
        id
        createdAt
        lastAuthentication {
          id
          createdAt
        }
      }
    `,
    session
  );

  const lastAuthentication = data.lastAuthentication?.createdAt;
  const createdAt = data.createdAt;

  return (
    <Block>
      {isCurrent && <Subtitle>Current session</Subtitle>}
      <Body>
        Started: <DateTime datetime={createdAt} />
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
