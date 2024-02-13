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
import { useMutation } from "urql";

import { FragmentType, graphql, useFragment } from "../gql";
import { Oauth2ApplicationType } from "../gql/graphql";
import { getDeviceIdFromScope } from "../utils/deviceIdFromScope";
import { DeviceType } from "../utils/parseUserAgent";

import { Session } from "./Session";
import EndSessionButton from "./Session/EndSessionButton";

export const FRAGMENT = graphql(/* GraphQL */ `
  fragment OAuth2Session_session on Oauth2Session {
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
    return DeviceType.Web;
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
  const data = useFragment(FRAGMENT, session);
  const [, endSession] = useMutation(END_SESSION_MUTATION);

  const onSessionEnd = async (): Promise<void> => {
    await endSession({ id: data.id });
  };

  const deviceId = getDeviceIdFromScope(data.scope);

  const createdAt = parseISO(data.createdAt);
  const finishedAt = data.finishedAt ? parseISO(data.finishedAt) : undefined;
  const lastActiveAt = data.lastActiveAt
    ? parseISO(data.lastActiveAt)
    : undefined;

  const deviceType = getDeviceTypeFromClientAppType(
    data.client.applicationType,
  );

  return (
    <Session
      id={data.id}
      name={deviceId}
      createdAt={createdAt}
      finishedAt={finishedAt}
      clientName={data.client.clientName || data.client.clientId || undefined}
      clientLogoUri={data.client.logoUri || undefined}
      deviceType={deviceType}
      lastActiveIp={data.lastActiveIp || undefined}
      lastActiveAt={lastActiveAt}
    >
      {!data.finishedAt && <EndSessionButton endSession={onSessionEnd} />}
    </Session>
  );
};

export default OAuth2Session;
