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

import { parseISO } from "date-fns";
import { atom, useSetAtom } from "jotai";
import { atomFamily } from "jotai/utils";
import { atomWithMutation } from "jotai-urql";
import { useCallback } from "react";

import { FragmentType, graphql, useFragment } from "../gql";
import {
  parseUserAgent,
  sessionNameFromDeviceInformation,
} from "../utils/parseUserAgent";
import { useCurrentBrowserSessionId } from "../utils/session/useCurrentBrowserSessionId";

import EndSessionButton from "./Session/EndSessionButton";
import Session from "./Session/Session";

const FRAGMENT = graphql(/* GraphQL */ `
  fragment BrowserSession_session on BrowserSession {
    id
    createdAt
    finishedAt
    userAgent
    lastActiveIp
    lastActiveAt
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

export const endBrowserSessionFamily = atomFamily((id: string) => {
  const endSession = atomWithMutation(END_SESSION_MUTATION);

  // A proxy atom which pre-sets the id variable in the mutation
  const endSessionAtom = atom(
    (get) => get(endSession),
    (get, set) => set(endSession, { id }),
  );

  return endSessionAtom;
});

export const useEndBrowserSession = (
  sessionId: string,
  isCurrent: boolean,
): (() => Promise<void>) => {
  const endSession = useSetAtom(endBrowserSessionFamily(sessionId));

  const onSessionEnd = useCallback(async (): Promise<void> => {
    await endSession();
    if (isCurrent) {
      window.location.reload();
    }
  }, [isCurrent, endSession]);

  return onSessionEnd;
};

type Props = {
  session: FragmentType<typeof FRAGMENT>;
};

const BrowserSession: React.FC<Props> = ({ session }) => {
  const currentBrowserSessionId = useCurrentBrowserSessionId();
  const data = useFragment(FRAGMENT, session);
  const isCurrent = data.id === currentBrowserSessionId;

  const onSessionEnd = useEndBrowserSession(data.id, isCurrent);

  const createdAt = parseISO(data.createdAt);
  const finishedAt = data.finishedAt ? parseISO(data.finishedAt) : undefined;
  const lastActiveAt = data.lastActiveAt
    ? parseISO(data.lastActiveAt)
    : undefined;
  const deviceInformation = parseUserAgent(data.userAgent || undefined);
  const sessionName =
    sessionNameFromDeviceInformation(deviceInformation) || "Browser session";

  return (
    <Session
      id={data.id}
      name={sessionName}
      createdAt={createdAt}
      finishedAt={finishedAt}
      isCurrent={isCurrent}
      deviceType={deviceInformation?.deviceType}
      lastActiveIp={data.lastActiveIp || undefined}
      lastActiveAt={lastActiveAt}
      link={{ type: "browser-session", id: data.id }}
    >
      {!data.finishedAt && <EndSessionButton endSession={onSessionEnd} />}
    </Session>
  );
};

export default BrowserSession;
