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

import { FragmentType, graphql, useFragment } from "../gql";
import { Link } from "../routing";

import { Session } from "./Session";
import EndSessionButton from "./Session/EndSessionButton";

export const FRAGMENT = graphql(/* GraphQL */ `
  fragment CompatSession_session on CompatSession {
    id
    createdAt
    deviceId
    finishedAt
    lastActiveIp
    lastActiveAt
    ssoLogin {
      id
      redirectUri
    }
  }
`);

const END_SESSION_MUTATION = graphql(/* GraphQL */ `
  mutation EndCompatSession($id: ID!) {
    endCompatSession(input: { compatSessionId: $id }) {
      status
      compatSession {
        id
        finishedAt
      }
    }
  }
`);

export const endCompatSessionFamily = atomFamily((id: string) => {
  const endCompatSession = atomWithMutation(END_SESSION_MUTATION);

  // A proxy atom which pre-sets the id variable in the mutation
  const endCompatSessionAtom = atom(
    (get) => get(endCompatSession),
    (get, set) => set(endCompatSession, { id }),
  );

  return endCompatSessionAtom;
});

export const simplifyUrl = (url: string): string => {
  let parsed;
  try {
    parsed = new URL(url);
  } catch (e) {
    // Not a valid URL, return the original
    return url;
  }

  // Clear out the search params and hash
  parsed.search = "";
  parsed.hash = "";

  if (parsed.protocol === "https:") {
    return parsed.hostname;
  }

  // Return the simplified URL
  return parsed.toString();
};

const CompatSession: React.FC<{
  session: FragmentType<typeof FRAGMENT>;
}> = ({ session }) => {
  const data = useFragment(FRAGMENT, session);
  const endCompatSession = useSetAtom(endCompatSessionFamily(data.id));

  const onSessionEnd = async (): Promise<void> => {
    await endCompatSession();
  };

  const sessionName = (
    <Link route={{ type: "session", id: data.deviceId }}>{data.deviceId}</Link>
  );

  const clientName = data.ssoLogin?.redirectUri
    ? simplifyUrl(data.ssoLogin.redirectUri)
    : undefined;

  const createdAt = parseISO(data.createdAt);
  const finishedAt = data.finishedAt ? parseISO(data.finishedAt) : undefined;
  const lastActiveAt = data.lastActiveAt
    ? parseISO(data.lastActiveAt)
    : undefined;

  return (
    <Session
      id={data.id}
      name={sessionName}
      createdAt={createdAt}
      finishedAt={finishedAt}
      clientName={clientName}
      lastActiveIp={data.lastActiveIp || undefined}
      lastActiveAt={lastActiveAt}
    >
      {!data.finishedAt && <EndSessionButton endSession={onSessionEnd} />}
    </Session>
  );
};

export default CompatSession;
