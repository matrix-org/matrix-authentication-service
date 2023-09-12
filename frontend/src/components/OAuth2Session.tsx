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

import { atom, useSetAtom } from "jotai";
import { atomFamily } from "jotai/utils";
import { atomWithMutation } from "jotai-urql";

import { FragmentType, graphql, useFragment } from "../gql";
import { Link } from "../routing";
import { getDeviceIdFromScope } from "../utils/deviceIdFromScope";

import { Session } from "./Session";
import EndSessionButton from "./Session/EndSessionButton";

export const OAUTH2_SESSION_FRAGMENT = graphql(/* GraphQL */ `
  fragment OAuth2Session_session on Oauth2Session {
    __typename
    id
    scope
    createdAt
    finishedAt
    client {
      id
      clientId
      clientName
      clientUri
      logoUri
    }
  }
`);

const END_SESSION_MUTATION = graphql(/* GraphQL */ `
  mutation EndOAuth2Session($id: ID!) {
    endOauth2Session(input: { oauth2SessionId: $id }) {
      status
      oauth2Session {
        id
        ...OAuth2Session_session
      }
    }
  }
`);

export const endSessionFamily = atomFamily((id: string) => {
  const endSession = atomWithMutation(END_SESSION_MUTATION);

  // A proxy atom which pre-sets the id variable in the mutation
  const endSessionAtom = atom(
    (get) => get(endSession),
    (get, set) => set(endSession, { id }),
  );

  return endSessionAtom;
});

type Props = {
  session: FragmentType<typeof OAUTH2_SESSION_FRAGMENT>;
};

const OAuth2Session: React.FC<Props> = ({ session }) => {
  const data = useFragment(OAUTH2_SESSION_FRAGMENT, session);
  const endSession = useSetAtom(endSessionFamily(data.id));

  const onSessionEnd = async (): Promise<void> => {
    await endSession();
  };

  const deviceId = getDeviceIdFromScope(data.scope);

  const name = deviceId && (
    <Link route={{ type: "session", id: deviceId }}>{deviceId}</Link>
  );

  return (
    <Session
      id={data.id}
      name={name}
      createdAt={data.createdAt}
      finishedAt={data.finishedAt || undefined}
      clientName={data.client.clientName || undefined}
      clientLogoUri={data.client.logoUri || undefined}
    >
      {!data.finishedAt && <EndSessionButton endSession={onSessionEnd} />}
    </Session>
  );
};

export default OAuth2Session;
