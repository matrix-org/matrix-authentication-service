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

import { parseISO } from "date-fns";
import { useSetAtom } from "jotai";
import { useTranslation } from "react-i18next";

import { FragmentType, graphql, useFragment } from "../../gql";
import BlockList from "../BlockList/BlockList";
import { endCompatSessionFamily, simplifyUrl } from "../CompatSession";
import DateTime from "../DateTime";
import ExternalLink from "../ExternalLink/ExternalLink";
import EndSessionButton from "../Session/EndSessionButton";
import LastActive from "../Session/LastActive";

import SessionDetails from "./SessionDetails";
import SessionHeader from "./SessionHeader";

export const FRAGMENT = graphql(/* GraphQL */ `
  fragment CompatSession_detail on CompatSession {
    id
    createdAt
    deviceId
    finishedAt
    lastActiveIp
    lastActiveAt
    ssoLogin {
      id
      redirectUri
    }
  }
`);

type Props = {
  session: FragmentType<typeof FRAGMENT>;
};

const CompatSessionDetail: React.FC<Props> = ({ session }) => {
  const data = useFragment(FRAGMENT, session);
  const endSession = useSetAtom(endCompatSessionFamily(data.id));
  const { t } = useTranslation();

  const onSessionEnd = async (): Promise<void> => {
    await endSession();
  };

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
      value: <code>{data.deviceId}</code>,
    },
    {
      label: t("frontend.session.signed_in_label"),
      value: <DateTime datetime={parseISO(data.createdAt)} />,
    },
    ...finishedAt,
    ...lastActiveAt,
    ...lastActiveIp,
  ];

  const clientDetails: { label: string; value: string | JSX.Element }[] = [];

  if (data.ssoLogin?.redirectUri) {
    clientDetails.push({
      label: t("frontend.compat_session_detail.name"),
      value: simplifyUrl(data.ssoLogin.redirectUri),
    });
    clientDetails.push({
      label: t("frontend.session.uri_label"),
      value: (
        <ExternalLink target="_blank" href={data.ssoLogin?.redirectUri}>
          {data.ssoLogin?.redirectUri}
        </ExternalLink>
      ),
    });
  }

  return (
    <BlockList>
      <SessionHeader
        backToRoute={{
          type: "sessions-overview",
        }}
      >
        {data.deviceId || data.id}
      </SessionHeader>
      <SessionDetails
        title={t("frontend.compat_session_detail.session_details_title")}
        details={sessionDetails}
      />
      {clientDetails.length > 0 ? (
        <SessionDetails
          title={t("frontend.compat_session_detail.client_details_title")}
          details={clientDetails}
        />
      ) : null}
      {!data.finishedAt && <EndSessionButton endSession={onSessionEnd} />}
    </BlockList>
  );
};

export default CompatSessionDetail;
