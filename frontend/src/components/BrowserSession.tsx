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

import { Button } from "@vector-im/compound-web";
import { atom, useSetAtom } from "jotai";
import { atomFamily } from "jotai/utils";
import { atomWithMutation } from "jotai-urql";
import { useTransition } from "react";

import { currentBrowserSessionIdAtom, currentUserIdAtom } from "../atoms";
import { FragmentType, graphql, useFragment } from "../gql";
import {
  parseUserAgent,
  sessionNameFromDeviceInformation,
} from "../utils/parseUserAgent";

import Session from "./Session/Session";

const FRAGMENT = graphql(/* GraphQL */ `
  fragment BrowserSession_session on BrowserSession {
    id
    createdAt
    finishedAt
    userAgent
    lastAuthentication {
      id
      createdAt
    }
  }
`);

const END_SESSION_MUTATION = graphql(/* GraphQL */ `
  mutation EndBrowserSession($id: ID!) {
    endBrowserSession(input: { browserSessionId: $id }) {
      status
      browserSession {
        id
        ...BrowserSession_session
      }
    }
  }
`);

const endSessionFamily = atomFamily((id: string) => {
  const endSession = atomWithMutation(END_SESSION_MUTATION);

  // A proxy atom which pre-sets the id variable in the mutation
  const endSessionAtom = atom(
    (get) => get(endSession),
    (get, set) => set(endSession, { id }),
  );

  return endSessionAtom;
});

type Props = {
  session: FragmentType<typeof FRAGMENT>;
  isCurrent: boolean;
};

const BrowserSession: React.FC<Props> = ({ session, isCurrent }) => {
  const data = useFragment(FRAGMENT, session);
  const [pending, startTransition] = useTransition();
  const endSession = useSetAtom(endSessionFamily(data.id));

  // Pull those atoms to reset them when the current session is ended
  const currentUserId = useSetAtom(currentUserIdAtom);
  const currentBrowserSessionId = useSetAtom(currentBrowserSessionIdAtom);

  const createdAt = data.createdAt;

  const onSessionEnd = (): void => {
    startTransition(() => {
      endSession().then(() => {
        if (isCurrent) {
          currentBrowserSessionId({
            requestPolicy: "network-only",
          });
          currentUserId({
            requestPolicy: "network-only",
          });
        }
      });
    });
  };

  const deviceInformation = parseUserAgent(data.userAgent || undefined);
  const sessionName =
    sessionNameFromDeviceInformation(deviceInformation) || "Browser session";

  return (
    <Session
      id={data.id}
      name={sessionName}
      createdAt={createdAt}
      finishedAt={data.finishedAt}
      isCurrent={isCurrent}
    >
      {!data.finishedAt && (
        <Button
          kind="destructive"
          size="sm"
          onClick={onSessionEnd}
          disabled={pending}
        >
          Sign out
        </Button>
      )}
    </Session>
  );
};

export default BrowserSession;
