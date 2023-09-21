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

import { parseISO } from "date-fns";
import { useSetAtom } from "jotai";

import { FragmentType, graphql, useFragment } from "../../gql";
import { Link } from "../../routing";
import { getDeviceIdFromScope } from "../../utils/deviceIdFromScope";
import BlockList from "../BlockList/BlockList";
import DateTime from "../DateTime";
import { endSessionFamily } from "../OAuth2Session";
import ClientAvatar from "../Session/ClientAvatar";
import EndSessionButton from "../Session/EndSessionButton";
import LastActive from "../Session/LastActive";

import SessionDetails from "./SessionDetails";
import SessionHeader from "./SessionHeader";

export const FRAGMENT = graphql(/* GraphQL */ `
  fragment OAuth2Session_detail on Oauth2Session {
    id
    scope
    createdAt
    finishedAt
    lastActiveIp
    lastActiveAt
    client {
      id
      clientId
      clientName
      clientUri
      logoUri
    }
  }
`);

type Props = {
  session: FragmentType<typeof FRAGMENT>;
};

const OAuth2SessionDetail: React.FC<Props> = ({ session }) => {
  const data = useFragment(FRAGMENT, session);
  const endSession = useSetAtom(endSessionFamily(data.id));

  const onSessionEnd = async (): Promise<void> => {
    await endSession();
  };

  const deviceId = getDeviceIdFromScope(data.scope);

  const scopes = data.scope.split(" ");

  const finishedAt = data.finishedAt
    ? [
        {
          label: "Finished",
          value: <DateTime datetime={parseISO(data.createdAt)} />,
        },
      ]
    : [];

  const lastActiveIp = data.lastActiveIp
    ? [{ label: "IP Address", value: <code>{data.lastActiveIp}</code> }]
    : [];

  const lastActiveAt = data.lastActiveAt
    ? [
        {
          label: "Last Active",
          value: <LastActive lastActive={parseISO(data.lastActiveAt)} />,
        },
      ]
    : [];

  const sessionDetails = [
    { label: "ID", value: <code>{data.id}</code> },
    { label: "Device ID", value: <code>{deviceId}</code> },
    { label: "Signed in", value: <DateTime datetime={data.createdAt} /> },
    ...finishedAt,
    ...lastActiveAt,
    ...lastActiveIp,
    {
      label: "Scopes",
      value: (
        <span>
          {scopes.map((scope) => (
            <code key={scope}>{scope}</code>
          ))}
        </span>
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
        <a target="_blank" href={data.client.clientUri || undefined}>
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
