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

import Block from "./Block";
import DateTime from "./DateTime";
import { Body, Bold, Code } from "./Typography";

const FRAGMENT = graphql(/* GraphQL */ `
  fragment CompatSsoLogin_login on CompatSsoLogin {
    id
    redirectUri
    createdAt
    session {
      id
      ...CompatSsoLogin_session
      createdAt
      deviceId
      finishedAt
    }
  }
`);

const SESSION_FRAGMENT = graphql(/* GraphQL */ `
  fragment CompatSsoLogin_session on CompatSession {
    id
    createdAt
    deviceId
    finishedAt
  }
`);

const END_SESSION_MUTATION = graphql(/* GraphQL */ `
  mutation EndCompatSession($id: ID!) {
    endCompatSession(input: { compatSessionId: $id }) {
      status
      compatSession {
        id
        ...CompatSsoLogin_session
      }
    }
  }
`);

const endCompatSessionFamily = atomFamily((id: string) => {
  const endCompatSession = atomWithMutation(END_SESSION_MUTATION);

  // A proxy atom which pre-sets the id variable in the mutation
  const endCompatSessionAtom = atom(
    (get) => get(endCompatSession),
    (get, set) => set(endCompatSession, { id })
  );

  return endCompatSessionAtom;
});

type Props = {
  login: FragmentType<typeof FRAGMENT>;
};

const CompatSession: React.FC<{
  session: FragmentType<typeof SESSION_FRAGMENT>;
}> = ({ session }) => {
  const [pending, startTransition] = useTransition();
  const data = useFragment(SESSION_FRAGMENT, session);
  const endCompatSession = useSetAtom(endCompatSessionFamily(data.id));

  const onSessionEnd = () => {
    startTransition(() => {
      endCompatSession();
    });
  };

  return (
    <>
      <Body>
        Started: <DateTime datetime={data.createdAt} />
      </Body>
      {data.finishedAt ? (
        <div className="text-alert font-semibold">
          Finished: <DateTime datetime={data.finishedAt} />
        </div>
      ) : null}
      <Body>
        Device ID: <Code>{data.deviceId}</Code>
      </Body>
      {data.finishedAt ? null : (
        <Button
          className="mt-2"
          size="sm"
          disabled={pending}
          onClick={onSessionEnd}
          kind="destructive"
        >
          End session
        </Button>
      )}
    </>
  );
};

const CompatSsoLogin: React.FC<Props> = ({ login }) => {
  const data = useFragment(FRAGMENT, login);

  return (
    <Block>
      <Body>
        Requested: <DateTime datetime={data.createdAt} />
      </Body>
      <Body>
        Redirect URI: <Bold>{data.redirectUri}</Bold>
      </Body>
      {data.session && <CompatSession session={data.session} />}
    </Block>
  );
};

export default CompatSsoLogin;
