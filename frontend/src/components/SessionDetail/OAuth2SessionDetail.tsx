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

import { H3, Button } from "@vector-im/compound-web";
import { useSetAtom } from "jotai";
import { useTransition } from "react";

import { FragmentType, useFragment } from "../../gql";
import { getDeviceIdFromScope } from "../../utils/deviceIdFromScope";
import BlockList from "../BlockList/BlockList";
import DateTime from "../DateTime";
import {
  OAUTH2_SESSION_FRAGMENT,
  Oauth2SessionType,
  endSessionFamily,
} from "../OAuth2Session";

import SessionDetails from "./SessionDetails";

type Props = {
  session: FragmentType<typeof OAUTH2_SESSION_FRAGMENT>;
};

const OAuth2SessionDetail: React.FC<Props> = ({ session }) => {
  const [pending, startTransition] = useTransition();
  const data = useFragment(
    OAUTH2_SESSION_FRAGMENT,
    session,
  ) as Oauth2SessionType;
  const endSession = useSetAtom(endSessionFamily(data.id));

  // @TODO(kerrya) make this wait for session refresh properly
  // https://github.com/matrix-org/matrix-authentication-service/issues/1533
  const onSessionEnd = (): void => {
    startTransition(() => {
      endSession();
    });
  };

  const deviceId = getDeviceIdFromScope(data.scope);

  const scopes = data.scope.split(" ");

  const finishedAt = data.finishedAt
    ? [{ label: "Finished", value: <DateTime datetime={data.createdAt} /> }]
    : [];
  const sessionDetails = [
    { label: "ID", value: <code>{data.id}</code> },
    { label: "Device ID", value: <code>{deviceId}</code> },
    { label: "Signed in", value: <DateTime datetime={data.createdAt} /> },
    ...finishedAt,
    {
      label: "Scopes",
      value: (
        <>
          {scopes.map((scope) => (
            <p key={scope}>
              <code>{scope}</code>
            </p>
          ))}
        </>
      ),
    },
  ];

  const clientDetails = [
    { label: "Name", value: data.client.clientName },
    { label: "ID", value: <code>{data.client.clientId}</code> },
    {
      label: "Uri",
      value: (
        <a target="_blank" href={data.client.clientUri}>
          {data.client.clientUri}
        </a>
      ),
    },
  ];

  return (
    <div>
      <BlockList>
        <H3>{deviceId || data.id}</H3>
        <SessionDetails title="Session" details={sessionDetails} />
        <SessionDetails title="Client" details={clientDetails} />
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
      </BlockList>
    </div>
  );
};

export default OAuth2SessionDetail;
