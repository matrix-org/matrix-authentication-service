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

import { Badge } from "@vector-im/compound-web";
import { parseISO } from "date-fns";
import { useTranslation } from "react-i18next";

import { FragmentType, graphql, useFragment } from "../../gql";
import BlockList from "../BlockList/BlockList";
import { useEndBrowserSession } from "../BrowserSession";
import DateTime from "../DateTime";
import EndSessionButton from "../Session/EndSessionButton";

import styles from "./BrowserSessionDetail.module.css";
import SessionDetails from "./SessionDetails";
import SessionHeader from "./SessionHeader";

const FRAGMENT = graphql(/* GraphQL */ `
  fragment BrowserSession_detail on BrowserSession {
    id
    createdAt
    finishedAt
    userAgent {
      name
      model
      os
    }
    lastActiveIp
    lastActiveAt
    lastAuthentication {
      id
      createdAt
    }
    user {
      id
      username
    }
  }
`);

type Props = {
  session: FragmentType<typeof FRAGMENT>;
  isCurrent: boolean;
};

const BrowserSessionDetail: React.FC<Props> = ({ session, isCurrent }) => {
  const data = useFragment(FRAGMENT, session);
  const { t } = useTranslation();

  const onSessionEnd = useEndBrowserSession(data.id, isCurrent);

  let sessionName = "Browser session";
  if (data.userAgent) {
    if (data.userAgent.model && data.userAgent.name) {
      sessionName = `${data.userAgent.name} on ${data.userAgent.model}`;
    } else if (data.userAgent.name && data.userAgent.os) {
      sessionName = `${data.userAgent.name} on ${data.userAgent.os}`;
    } else if (data.userAgent.name) {
      sessionName = data.userAgent.name;
    }
  }

  const finishedAt = data.finishedAt
    ? [
        {
          label: t("frontend.session.finished_label"),
          value: <DateTime datetime={parseISO(data.finishedAt)} />,
        },
      ]
    : [];

  const sessionDetails = [...finishedAt];

  return (
    <BlockList>
      {isCurrent && (
        <Badge className={styles.currentBadge} kind="success">
          {t("frontend.browser_session_details.current_badge")}
        </Badge>
      )}
      <SessionHeader to="/sessions/browsers">{sessionName}</SessionHeader>
      <SessionDetails
        title={t("frontend.session.title")}
        lastActive={data.lastActiveAt ? parseISO(data.lastActiveAt) : undefined}
        signedIn={
          data.lastAuthentication
            ? parseISO(data.lastAuthentication.createdAt)
            : undefined
        }
        ipAddress={data.lastActiveIp ?? undefined}
        details={sessionDetails}
      />
      {!data.finishedAt && <EndSessionButton endSession={onSessionEnd} />}
    </BlockList>
  );
};

export default BrowserSessionDetail;
