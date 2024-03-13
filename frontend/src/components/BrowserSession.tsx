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

import IconChrome from "@browser-logos/chrome/chrome.svg?url";
import IconFirefox from "@browser-logos/firefox/firefox.svg?url";
import IconSafari from "@browser-logos/safari/safari.svg?url";
import { Badge } from "@vector-im/compound-web";
import { parseISO } from "date-fns";
import { useCallback } from "react";
import { useTranslation } from "react-i18next";
import { useMutation } from "urql";

import { FragmentType, graphql, useFragment } from "../gql";
import { DeviceType } from "../gql/graphql";

import DateTime from "./DateTime";
import EndSessionButton from "./Session/EndSessionButton";
import LastActive from "./Session/LastActive";
import * as Card from "./SessionCard";

const FRAGMENT = graphql(/* GraphQL */ `
  fragment BrowserSession_session on BrowserSession {
    id
    createdAt
    finishedAt
    userAgent {
      raw
      name
      os
      model
      deviceType
    }
    lastActiveIp
    lastActiveAt
    lastAuthentication {
      id
      createdAt
    }
  }
`);

const END_SESSION_MUTATION = graphql(/* GraphQL */ `
  mutation EndBrowserSession($id: ID!) {
    endBrowserSession(input: { browserSessionId: $id }) {
      status
      browserSession {
        id
        ...BrowserSession_session
      }
    }
  }
`);

export const useEndBrowserSession = (
  sessionId: string,
  isCurrent: boolean,
): (() => Promise<void>) => {
  const [, endSession] = useMutation(END_SESSION_MUTATION);

  const onSessionEnd = useCallback(async (): Promise<void> => {
    await endSession({ id: sessionId });
    if (isCurrent) {
      window.location.reload();
    }
  }, [isCurrent, endSession, sessionId]);

  return onSessionEnd;
};

export const browserLogoUri = (browser?: string): string | undefined => {
  const lcBrowser = browser?.toLowerCase();

  if (lcBrowser?.includes("chrome") || lcBrowser?.includes("chromium")) {
    return IconChrome;
  }

  if (lcBrowser?.includes("firefox")) {
    return IconFirefox;
  }

  if (lcBrowser?.includes("safari")) {
    return IconSafari;
  }
};

type Props = {
  session: FragmentType<typeof FRAGMENT>;
  isCurrent: boolean;
};

const BrowserSession: React.FC<Props> = ({ session, isCurrent }) => {
  const data = useFragment(FRAGMENT, session);
  const { t } = useTranslation();

  const onSessionEnd = useEndBrowserSession(data.id, isCurrent);

  const deviceType = data.userAgent?.deviceType ?? DeviceType.Unknown;

  let deviceName: string | null = null;
  let clientName: string | null = null;

  // If we have a model, use that as the device name, and the browser (+ OS) as the client name
  if (data.userAgent?.model) {
    deviceName = data.userAgent.model;
    if (data.userAgent?.name) {
      if (data.userAgent?.os) {
        clientName = t("frontend.session.name_for_platform", {
          name: data.userAgent.name,
          platform: data.userAgent.os,
        });
      } else {
        clientName = data.userAgent.name;
      }
    }
  } else {
    // Else use the browser as the device name
    deviceName = data.userAgent?.name ?? t("frontend.session.unknown_browser");
    // and if we have an OS, use that as the client name
    clientName = data.userAgent?.os ?? null;
  }

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
          {clientName && (
            <Card.Client
              name={clientName}
              logoUri={browserLogoUri(data.userAgent?.name ?? undefined)}
            />
          )}
        </Card.Header>

        <Card.Metadata>
          {lastActiveAt && !isCurrent && (
            <Card.Info label={t("frontend.session.last_active_label")}>
              <LastActive lastActive={lastActiveAt} />
            </Card.Info>
          )}

          <Card.Info label={t("frontend.session.signed_in_label")}>
            <DateTime datetime={createdAt} />
          </Card.Info>

          {isCurrent && (
            <Badge kind="success" className="self-center">
              {t("frontend.session.current")}
            </Badge>
          )}
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

export default BrowserSession;
