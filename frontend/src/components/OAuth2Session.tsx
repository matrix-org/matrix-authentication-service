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

import { FragmentType, graphql, useFragment } from "../gql";
import { getDeviceIdFromScope } from "../utils/deviceIdFromScope";
// import LoadingSpinner from "./LoadingSpinner/LoadingSpinner";
import { Session } from "./Session/Session";

const FRAGMENT = graphql(/* GraphQL */ `
  fragment OAuth2Session_session on Oauth2Session {
    id
    scope
    createdAt
    finishedAt
    client {
      id
      clientId
      clientName
      clientUri
    }
  }
`);

type Oauth2SessionType = {
  id: string;
  scope: string;
  createdAt: number;
  finishedAt?: number;
  client: {
    id: string;
    clientId: string;
    clientName: string;
    clientUri: string;
  }
}

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
};

const OAuth2Session: React.FC<Props> = ({ session }) => {
  const [pending, startTransition] = useTransition();
  const data = useFragment<Oauth2SessionType>(FRAGMENT, session);
  const endSession = useSetAtom(endSessionFamily(data.id));

  // @TODO(kerrya) make this wait for session refresh properly
  // https://github.com/matrix-org/matrix-authentication-service/issues/1533
  const onSessionEnd = (): void => {
    startTransition(() => {
      endSession();
    });
  };

  const sessionName = getDeviceIdFromScope(data.scope);

  return (
    <Session
      id={data.id}
      name={sessionName}
      createdAt={data.createdAt}
      finishedAt={data.finishedAt}
      clientName={data.client.clientName}
    >
      {!data.finishedAt && (
        <Button
          kind="destructive"
          size="sm"
          onClick={onSessionEnd}
          disabled={pending}
        >
          {/* @TODO(kerrya) put this back after pending state works properly */}
          {/* { pending && <LoadingSpinner />} */}
          End session
        </Button>
      )}
    </Session>
  );
};

export default OAuth2Session;
