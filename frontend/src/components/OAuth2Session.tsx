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

import { Link } from "../Router";
import { FragmentType, graphql, useFragment } from "../gql";

import Block from "./Block";
import DateTime from "./DateTime";
import Typography, { Body, Bold, Code } from "./Typography";

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
    (get, set) => set(endSession, { id })
  );

  return endSessionAtom;
});

type Props = {
  session: FragmentType<typeof FRAGMENT>;
};

const API_SCOPE = "urn:matrix:org.matrix.msc2967.client:api:*";
const DEVICE_PREFIX = "urn:matrix:org.matrix.msc2967.client:device:";

const Scope: React.FC<{ scope: string }> = ({ scope }) => {
  if (scope === "openid") return <>OpenID</>;
  if (scope === "email") return <>Email</>;
  if (scope === "profile") return <>Profile</>;
  if (scope === API_SCOPE) return <>Matrix C-S API </>;

  if (scope.startsWith(DEVICE_PREFIX))
    return (
      <>
        Device <Code>{scope.slice(DEVICE_PREFIX.length)}</Code>
      </>
    );

  return <Code>{scope}</Code>;
};

const OAuth2Session: React.FC<Props> = ({ session }) => {
  const [pending, startTransition] = useTransition();
  const data = useFragment(FRAGMENT, session);
  const endSession = useSetAtom(endSessionFamily(data.id));

  const onSessionEnd = (): void => {
    startTransition(() => {
      endSession();
    });
  };

  return (
    <Block>
      <Typography variant="body" bold>
        <Link
          route={{ type: "client", id: data.client.id }}
          className="text-links hover:text-links/75"
        >
          Client ID: <Code>{data.client.clientId}</Code>
        </Link>
      </Typography>
      {data.client.clientName && (
        <Body>
          Client name: <Bold>{data.client.clientName}</Bold>
        </Body>
      )}
      <Typography variant="caption">
        Started <DateTime datetime={data.createdAt} />
      </Typography>
      {data.finishedAt && (
        <p className="text-alert font-semibold">
          Finished <DateTime datetime={data.finishedAt} />
        </p>
      )}
      <hr className="my-2 border-t-2 border-grey-300" />
      <div>
        <Typography variant="body" bold>
          Access:
        </Typography>
        <ul className="list-disc list-inside">
          {data.scope.split(" ").map((scope) => (
            <li key={scope}>
              <Scope scope={scope} />
            </li>
          ))}
        </ul>
      </div>
      {!data.finishedAt && (
        <Button
          kind="destructive"
          size="sm"
          className="mt-2"
          onClick={onSessionEnd}
          disabled={pending}
        >
          End session
        </Button>
      )}
    </Block>
  );
};

export default OAuth2Session;
