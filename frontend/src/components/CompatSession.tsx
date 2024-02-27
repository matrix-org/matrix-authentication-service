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
import { useTranslation } from "react-i18next";
import { useMutation } from "urql";

import { FragmentType, graphql, useFragment } from "../gql";
import { DeviceType } from "../gql/graphql";

import DateTime from "./DateTime";
import EndSessionButton from "./Session/EndSessionButton";
import LastActive from "./Session/LastActive";
import * as Card from "./SessionCard";

export const FRAGMENT = graphql(/* GraphQL */ `
  fragment CompatSession_session on CompatSession {
    id
    createdAt
    deviceId
    finishedAt
    lastActiveIp
    lastActiveAt
    userAgent {
      name
      os
      model
      deviceType
    }
    ssoLogin {
      id
      redirectUri
    }
  }
`);

export const END_SESSION_MUTATION = graphql(/* GraphQL */ `
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

export const simplifyUrl = (url: string): string => {
  let parsed: URL;
  try {
    parsed = new URL(url);
  } catch (e) {
    // Not a valid URL, return the original
    return url;
  }

  // Clear out the search params and hash
  parsed.search = "";
  parsed.hash = "";

  if (parsed.protocol === "https:") {
    return parsed.hostname;
  }

  // Return the simplified URL
  return parsed.toString();
};

const CompatSession: React.FC<{
  session: FragmentType<typeof FRAGMENT>;
}> = ({ session }) => {
  const { t } = useTranslation();
  const data = useFragment(FRAGMENT, session);
  const [, endCompatSession] = useMutation(END_SESSION_MUTATION);

  const onSessionEnd = async (): Promise<void> => {
    await endCompatSession({ id: data.id });
  };

  const clientName = data.ssoLogin?.redirectUri
    ? simplifyUrl(data.ssoLogin.redirectUri)
    : undefined;

  const deviceType = data.userAgent?.deviceType ?? DeviceType.Unknown;

  const deviceName =
    data.userAgent?.model ??
    (data.userAgent?.name
      ? data.userAgent?.os
        ? t("frontend.session.name_for_platform", {
            name: data.userAgent.name,
            platform: data.userAgent.os,
          })
        : data.userAgent.name
      : t("frontend.session.unknown_device"));

  const createdAt = parseISO(data.createdAt);
  const lastActiveAt = data.lastActiveAt
    ? parseISO(data.lastActiveAt)
    : undefined;

  return (
    <Card.Root>
      <Card.LinkBody
        to="/sessions/$id"
        params={{ id: data.id }}
        disabled={!!data.finishedAt}
      >
        <Card.Header type={deviceType}>
          <Card.Name name={deviceName} />
          {clientName && <Card.Client name={clientName} />}
        </Card.Header>

        <Card.Metadata>
          {lastActiveAt && (
            <Card.Info label={t("frontend.session.last_active_label")}>
              <LastActive lastActive={lastActiveAt} />
            </Card.Info>
          )}
          <Card.Info label={t("frontend.session.signed_in_label")}>
            <DateTime datetime={createdAt} />
          </Card.Info>
          <Card.Info label={t("frontend.session.device_id_label")}>
            {data.deviceId}
          </Card.Info>
        </Card.Metadata>
      </Card.LinkBody>

      {!data.finishedAt && (
        <Card.Action>
          <EndSessionButton endSession={onSessionEnd}>
            <Card.Body compact>
              <Card.Header type={deviceType}>
                <Card.Name name={deviceName} />
                {clientName && <Card.Client name={clientName} />}
              </Card.Header>
            </Card.Body>
          </EndSessionButton>
        </Card.Action>
      )}
    </Card.Root>
  );
};

export default CompatSession;
