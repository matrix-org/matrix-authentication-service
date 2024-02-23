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
import { useCallback } from "react";
import { useMutation } from "urql";

import { FragmentType, graphql, useFragment } from "../gql";

import EndSessionButton from "./Session/EndSessionButton";
import Session from "./Session/Session";

const FRAGMENT = graphql(/* GraphQL */ `
  fragment BrowserSession_session on BrowserSession {
    id
    createdAt
    finishedAt
    userAgent {
      raw
      name
      os
      model
      deviceType
    }
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

export const useEndBrowserSession = (
  sessionId: string,
  isCurrent: boolean,
): (() => Promise<void>) => {
  const [, endSession] = useMutation(END_SESSION_MUTATION);

  const onSessionEnd = useCallback(async (): Promise<void> => {
    await endSession({ id: sessionId });
    if (isCurrent) {
      window.location.reload();
    }
  }, [isCurrent, endSession, sessionId]);

  return onSessionEnd;
};

type Props = {
  session: FragmentType<typeof FRAGMENT>;
  isCurrent: boolean;
};

const BrowserSession: React.FC<Props> = ({ session, isCurrent }) => {
  const data = useFragment(FRAGMENT, session);

  const onSessionEnd = useEndBrowserSession(data.id, isCurrent);

  const createdAt = parseISO(data.createdAt);
  const finishedAt = data.finishedAt ? parseISO(data.finishedAt) : undefined;
  const lastActiveAt = data.lastActiveAt
    ? parseISO(data.lastActiveAt)
    : undefined;
  let sessionName = "Browser session";
  if (data.userAgent) {
    if (data.userAgent.model && data.userAgent.name) {
      sessionName = `${data.userAgent.name} on ${data.userAgent.model}`;
    } else if (data.userAgent.name && data.userAgent.os) {
      sessionName = `${data.userAgent.name} on ${data.userAgent.os}`;
    } else if (data.userAgent.name) {
      sessionName = data.userAgent.name;
    }
  }

  return (
    <Session
      id={data.id}
      name={sessionName}
      createdAt={createdAt}
      finishedAt={finishedAt}
      isCurrent={isCurrent}
      deviceType={data.userAgent?.deviceType}
      lastActiveIp={data.lastActiveIp || undefined}
      lastActiveAt={lastActiveAt}
    >
      {!data.finishedAt && <EndSessionButton endSession={onSessionEnd} />}
    </Session>
  );
};

export default BrowserSession;
