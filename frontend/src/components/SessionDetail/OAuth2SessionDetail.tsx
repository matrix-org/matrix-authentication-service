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
import { useTranslation } from "react-i18next";
import { useMutation } from "urql";

import { FragmentType, graphql, useFragment } from "../../gql";
import { getDeviceIdFromScope } from "../../utils/deviceIdFromScope";
import BlockList from "../BlockList/BlockList";
import DateTime from "../DateTime";
import { Link } from "../Link";
import { END_SESSION_MUTATION } from "../OAuth2Session";
import ClientAvatar from "../Session/ClientAvatar";
import EndSessionButton from "../Session/EndSessionButton";

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
  const [, endSession] = useMutation(END_SESSION_MUTATION);
  const { t } = useTranslation();

  const onSessionEnd = async (): Promise<void> => {
    await endSession({ id: data.id });
  };

  const deviceId = getDeviceIdFromScope(data.scope);

  const finishedAt = data.finishedAt
    ? [
        {
          label: t("frontend.session.finished_label"),
          value: <DateTime datetime={parseISO(data.finishedAt)} />,
        },
      ]
    : [];

  const sessionDetails = [...finishedAt];

  const clientTitle = (
    <Link to="/clients/$id" params={{ id: data.client.id }}>
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
      label: t("frontend.session.client_id_label"),
      value: <code>{data.client.clientId}</code>,
    },
    {
      label: t("frontend.session.uri_label"),
      value: (
        <a
          target="_blank"
          rel="noreferrer"
          href={data.client.clientUri || undefined}
        >
          {data.client.clientUri}
        </a>
      ),
    },
  ];

  return (
    <BlockList>
      <SessionHeader to="/sessions">{deviceId || data.id}</SessionHeader>
      <SessionDetails
        title={t("frontend.session.title")}
        lastActive={data.lastActiveAt ? parseISO(data.lastActiveAt) : undefined}
        signedIn={parseISO(data.createdAt)}
        deviceId={deviceId}
        ipAddress={data.lastActiveIp ?? undefined}
        scopes={data.scope.split(" ")}
        details={sessionDetails}
      />
      <SessionDetails title={clientTitle} details={clientDetails} />
      {!data.finishedAt && <EndSessionButton endSession={onSessionEnd} />}
    </BlockList>
  );
};

export default OAuth2SessionDetail;
