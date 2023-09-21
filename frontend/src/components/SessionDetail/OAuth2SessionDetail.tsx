// Copyright 2023 The Matrix.org Foundation C.I.C.
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

import { useSetAtom } from "jotai";

import { FragmentType, useFragment } from "../../gql";
import { Link } from "../../routing";
import { getDeviceIdFromScope } from "../../utils/deviceIdFromScope";
import BlockList from "../BlockList/BlockList";
import DateTime from "../DateTime";
import { OAUTH2_SESSION_FRAGMENT, endSessionFamily } from "../OAuth2Session";
import ClientAvatar from "../Session/ClientAvatar";
import EndSessionButton from "../Session/EndSessionButton";

import SessionDetails from "./SessionDetails";
import SessionHeader from "./SessionHeader";

type Props = {
  session: FragmentType<typeof OAUTH2_SESSION_FRAGMENT>;
};

const OAuth2SessionDetail: React.FC<Props> = ({ session }) => {
  const data = useFragment(OAUTH2_SESSION_FRAGMENT, session);
  const endSession = useSetAtom(endSessionFamily(data.id));

  const onSessionEnd = async (): Promise<void> => {
    await endSession();
  };

  const deviceId = getDeviceIdFromScope(data.scope);

  const scopes = data.scope.split(" ");

  const finishedAt = data.finishedAt
    ? [{ label: "Finished", value: <DateTime datetime={data.createdAt} /> }]
    : [];

  const ipAddress = data.ipAddress
    ? [{ label: "IP Address", value: <code>{data.ipAddress}</code> }]
    : [];

  const sessionDetails = [
    { label: "ID", value: <code>{data.id}</code> },
    { label: "Device ID", value: <code>{deviceId}</code> },
    { label: "Signed in", value: <DateTime datetime={data.createdAt} /> },
    ...finishedAt,
    ...ipAddress,
    {
      label: "Scopes",
      value: (
        <div>
          {scopes.map((scope) => (
            <code key={scope}>{scope}</code>
          ))}
        </div>
      ),
    },
  ];

  const clientTitle = (
    <Link route={{ type: "client", id: data.client.id }}>Client</Link>
  );
  const clientDetails = [
    {
      label: "Name",
      value: (
        <>
          <ClientAvatar
            name={data.client.clientName || data.client.clientId}
            logoUri={data.client.logoUri || undefined}
            size="var(--cpd-space-4x)"
          />
          {data.client.clientName}
        </>
      ),
    },
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
    <BlockList>
      <SessionHeader
        backToRoute={{
          type: "sessions-overview",
        }}
      >
        {deviceId || data.id}
      </SessionHeader>
      <SessionDetails title="Session" details={sessionDetails} />
      <SessionDetails title={clientTitle} details={clientDetails} />
      {!data.finishedAt && <EndSessionButton endSession={onSessionEnd} />}
    </BlockList>
  );
};

export default OAuth2SessionDetail;
