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

const LOGIN_FRAGMENT = graphql(/* GraphQL */ `
  fragment CompatSession_sso_login on CompatSsoLogin {
    id
    redirectUri
  }
`);

const FRAGMENT = graphql(/* GraphQL */ `
  fragment CompatSession_session on CompatSession {
    id
    createdAt
    deviceId
    finishedAt
    ssoLogin {
      id
      ...CompatSession_sso_login
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

const endCompatSessionFamily = atomFamily((id: string) => {
  const endCompatSession = atomWithMutation(END_SESSION_MUTATION);

  // A proxy atom which pre-sets the id variable in the mutation
  const endCompatSessionAtom = atom(
    (get) => get(endCompatSession),
    (get, set) => set(endCompatSession, { id }),
  );

  return endCompatSessionAtom;
});

const CompatSession: React.FC<{
  session: FragmentType<typeof FRAGMENT>;
}> = ({ session }) => {
  const [pending, startTransition] = useTransition();
  const data = useFragment(FRAGMENT, session);
  const endCompatSession = useSetAtom(endCompatSessionFamily(data.id));

  const onSessionEnd = (): void => {
    startTransition(() => {
      endCompatSession();
    });
  };

  return (
    <Block>
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
      {data.ssoLogin && <CompatSsoLogin login={data.ssoLogin} />}
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
    </Block>
  );
};

const CompatSsoLogin: React.FC<{
  login: FragmentType<typeof LOGIN_FRAGMENT>;
}> = ({ login }) => {
  const data = useFragment(LOGIN_FRAGMENT, login);

  return (
    <>
      <Body>
        Redirect URI: <Bold>{data.redirectUri}</Bold>
      </Body>
    </>
  );
};

export default CompatSession;
