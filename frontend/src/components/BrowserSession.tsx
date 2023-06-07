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

import IconWebBrowser from "@vector-im/compound-design-tokens/icons/web-browser.svg";
import { Body } from "@vector-im/compound-web";

import { FragmentType, graphql, useFragment } from "../gql";

import Block from "./Block";
import DateTime from "./DateTime";

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

  // const lastAuthentication = data.lastAuthentication?.createdAt;
  const createdAt = data.createdAt;

  return (
    <Block className="my-2">
      <IconWebBrowser
        className="session-icon float-left mr-2"
        width="24"
        height="24"
      />
      <Body size="md" weight="medium">
        {isCurrent ? (
          <>
            <strong>Current</strong> browser session
          </>
        ) : (
          <>Browser Session</>
        )}
      </Body>
      <div className="flex flex-row justify-between">
        <Body size="sm" className="secondary-text">
          Signed in <DateTime datetime={createdAt} />
        </Body>
        <Body as="a" size="sm" weight="medium" href="#" data-kind="critical">
          Sign out
        </Body>
      </div>
    </Block>
  );
};

export default BrowserSession;
