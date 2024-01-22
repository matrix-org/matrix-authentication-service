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
import { useTranslation } from "react-i18next";

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
  const { t } = useTranslation();

  const onSessionEnd = async (): Promise<void> => {
    await endSession();
  };

  const deviceId = getDeviceIdFromScope(data.scope);

  const scopes = data.scope.split(" ");

  const finishedAt = data.finishedAt
    ? [
        {
          label: t("frontend.session.finished_label"),
          value: <DateTime datetime={parseISO(data.finishedAt)} />,
        },
      ]
    : [];

  const lastActiveIp = data.lastActiveIp
    ? [
        {
          label: t("frontend.session.ip_label"),
          value: <code>{data.lastActiveIp}</code>,
        },
      ]
    : [];

  const lastActiveAt = data.lastActiveAt
    ? [
        {
          label: t("frontend.session.last_active_label"),
          value: <LastActive lastActive={parseISO(data.lastActiveAt)} />,
        },
      ]
    : [];

  const sessionDetails = [
    { label: t("frontend.session.id_label"), value: <code>{data.id}</code> },
    {
      label: t("frontend.session.device_id_label"),
      value: <code>{deviceId}</code>,
    },
    {
      label: t("frontend.session.signed_in_label"),
      value: <DateTime datetime={data.createdAt} />,
    },
    ...finishedAt,
    ...lastActiveAt,
    ...lastActiveIp,
    {
      label: t("frontend.session.scopes_label"),
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
    <Link route={{ type: "client", id: data.client.id }}>
      {t("frontend.oauth2_session_detail.client_title")}
    </Link>
  );
  const clientDetails = [
    {
      label: t("frontend.oauth2_session_detail.client_details_name"),
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
    {
      label: t("frontend.session.id_label"),
      value: <code>{data.client.clientId}</code>,
    },
    {
      label: t("frontend.session.uri_label"),
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
      <SessionDetails
        title={t("frontend.oauth2_session_detail.session_details_title")}
        details={sessionDetails}
      />
      <SessionDetails title={clientTitle} details={clientDetails} />
      {!data.finishedAt && <EndSessionButton endSession={onSessionEnd} />}
    </BlockList>
  );
};

export default OAuth2SessionDetail;
