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

import { FragmentType, useFragment } from "../../gql";
import { BROWSER_SESSION_DETAIL_FRAGMENT } from "../../pages/BrowserSession";
import {
  parseUserAgent,
  sessionNameFromDeviceInformation,
} from "../../utils/parseUserAgent";
import { useCurrentBrowserSessionId } from "../../utils/session/useCurrentBrowserSessionId";
import BlockList from "../BlockList/BlockList";
import { useEndBrowserSession } from "../BrowserSession";
import DateTime from "../DateTime";
import EndSessionButton from "../Session/EndSessionButton";

import styles from "./BrowserSessionDetail.module.css";
import SessionDetails from "./SessionDetails";
import SessionHeader from "./SessionHeader";

type Props = {
  session: FragmentType<typeof BROWSER_SESSION_DETAIL_FRAGMENT>;
};

const BrowserSessionDetail: React.FC<Props> = ({ session }) => {
  const data = useFragment(BROWSER_SESSION_DETAIL_FRAGMENT, session);
  const currentBrowserSessionId = useCurrentBrowserSessionId();

  const isCurrent = currentBrowserSessionId === data.id;
  const onSessionEnd = useEndBrowserSession(data.id, isCurrent);

  const deviceInformation = parseUserAgent(data.userAgent || undefined);
  const sessionName =
    sessionNameFromDeviceInformation(deviceInformation) || "Browser session";

  const finishedAt = data.finishedAt
    ? [{ label: "Finished", value: <DateTime datetime={data.finishedAt} /> }]
    : [];

  const lastAuthentication = data.lastAuthentication
    ? [
        {
          label: "Last Authentication",
          value: <DateTime datetime={data.lastAuthentication.createdAt} />,
        },
      ]
    : [];

  const sessionDetails = [
    { label: "ID", value: <code>{data.id}</code> },
    { label: "User ID", value: <code>{data.user.id}</code> },
    { label: "User Name", value: <code>{data.user.username}</code> },
    { label: "Signed in", value: <DateTime datetime={data.createdAt} /> },
    ...finishedAt,
    ...lastAuthentication,
  ];

  return (
    <BlockList>
      {isCurrent && (
        <Badge className={styles.currentBadge} kind="success">
          Current
        </Badge>
      )}
      <SessionHeader>{sessionName}</SessionHeader>
      <SessionDetails title="Session" details={sessionDetails} />
      {!data.finishedAt && <EndSessionButton endSession={onSessionEnd} />}
    </BlockList>
  );
};

export default BrowserSessionDetail;
