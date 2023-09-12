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

import { FragmentType } from "../../gql/fragment-masking";
import BlockList from "../BlockList/BlockList";
import BrowserSession, { BROWSER_SESSION_FRAGMENT } from "../BrowserSession";
import CompatSession, { COMPAT_SESSION_FRAGMENT } from "../CompatSession";
import OAuth2Session, { OAUTH2_SESSION_FRAGMENT } from "../OAuth2Session";

type GenericSessionType =
  | FragmentType<typeof BROWSER_SESSION_FRAGMENT>
  | FragmentType<typeof COMPAT_SESSION_FRAGMENT>
  | FragmentType<typeof OAUTH2_SESSION_FRAGMENT>;

const SessionList: React.FC<{
  sessionEdges: { cursor: string; node: GenericSessionType[] };
}> = ({ sessionEdges }) => {
  return (
    <BlockList>
      {sessionEdges.map((session) => {
        switch (session.node.__typename) {
          case "Oauth2Session":
            return (
              <OAuth2Session
                key={session.cursor}
                session={
                  session.node as FragmentType<typeof OAUTH2_SESSION_FRAGMENT>
                }
              />
            );
          case "CompatSession":
            return (
              <CompatSession key={session.cursor} session={session.node} />
            );
          case "BrowserSession":
            return (
              <BrowserSession key={session.cursor} session={session.node} />
            );
          default:
            throw new Error("Unexpected session type.");
        }
      })}
    </BlockList>
  );
};

export default SessionList;
