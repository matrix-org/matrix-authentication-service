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
import { DeviceType, Oauth2ApplicationType } from "../gql/graphql";
import { getDeviceIdFromScope } from "../utils/deviceIdFromScope";

import DateTime from "./DateTime";
import EndSessionButton from "./Session/EndSessionButton";
import LastActive from "./Session/LastActive";
import * as Card from "./SessionCard";

export const FRAGMENT = graphql(/* GraphQL */ `
  fragment OAuth2Session_session on Oauth2Session {
    id
    scope
    createdAt
    finishedAt
    lastActiveIp
    lastActiveAt

    userAgent {
      name
      model
      os
      deviceType
    }

    client {
      id
      clientId
      clientName
      applicationType
      logoUri
    }
  }
`);

export const END_SESSION_MUTATION = graphql(/* GraphQL */ `
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

const getDeviceTypeFromClientAppType = (
  appType?: Oauth2ApplicationType | null,
): DeviceType => {
  if (appType === Oauth2ApplicationType.Web) {
    return DeviceType.Pc;
  }
  if (appType === Oauth2ApplicationType.Native) {
    return DeviceType.Mobile;
  }
  return DeviceType.Unknown;
};

type Props = {
  session: FragmentType<typeof FRAGMENT>;
};

const OAuth2Session: React.FC<Props> = ({ session }) => {
  const { t } = useTranslation();
  const data = useFragment(FRAGMENT, session);
  const [, endSession] = useMutation(END_SESSION_MUTATION);

  const onSessionEnd = async (): Promise<void> => {
    await endSession({ id: data.id });
  };

  const deviceId = getDeviceIdFromScope(data.scope);

  const createdAt = parseISO(data.createdAt);
  const lastActiveAt = data.lastActiveAt
    ? parseISO(data.lastActiveAt)
    : undefined;

  const deviceType =
    (data.userAgent?.deviceType === DeviceType.Unknown
      ? null
      : data.userAgent?.deviceType) ??
    getDeviceTypeFromClientAppType(data.client.applicationType);

  const clientName = data.client.clientName || data.client.clientId;

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

  return (
    <Card.Root>
      <Card.LinkBody
        to="/sessions/$id"
        params={{ id: data.id }}
        disabled={!!data.finishedAt}
      >
        <Card.Header type={deviceType}>
          <Card.Name name={deviceName} />
          <Card.Client
            name={clientName}
            logoUri={data.client.logoUri ?? undefined}
          />
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
          {deviceId && (
            <Card.Info label={t("frontend.session.device_id_label")}>
              {deviceId}
            </Card.Info>
          )}
        </Card.Metadata>
      </Card.LinkBody>

      {!data.finishedAt && (
        <Card.Action>
          <EndSessionButton endSession={onSessionEnd}>
            <Card.Body compact>
              <Card.Header type={deviceType}>
                <Card.Name name={deviceName} />
                <Card.Client
                  name={clientName}
                  logoUri={data.client.logoUri ?? undefined}
                />
              </Card.Header>
            </Card.Body>
          </EndSessionButton>
        </Card.Action>
      )}
    </Card.Root>
  );
};

export default OAuth2Session;
