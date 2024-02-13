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

import { Link } from "@tanstack/react-router";
import { H6, Text, Badge } from "@vector-im/compound-web";
import { Trans, useTranslation } from "react-i18next";

import { DeviceType } from "../../utils/parseUserAgent";
import Block from "../Block";
import DateTime from "../DateTime";

import ClientAvatar from "./ClientAvatar";
import DeviceTypeIcon from "./DeviceTypeIcon";
import LastActive from "./LastActive";
import styles from "./Session.module.css";

const SessionMetadata: React.FC<React.ComponentProps<typeof Text>> = (
  props,
) => <Text {...props} size="sm" className={styles.sessionMetadata} />;

type SessionProps = {
  id: string;
  name?: string;
  createdAt: Date;
  finishedAt?: Date;
  clientName?: string;
  clientLogoUri?: string;
  isCurrent?: boolean;
  deviceType?: DeviceType;
  lastActiveIp?: string;
  lastActiveAt?: Date;
};

const Session: React.FC<React.PropsWithChildren<SessionProps>> = ({
  id,
  name,
  createdAt,
  finishedAt,
  clientName,
  clientLogoUri,
  lastActiveIp,
  lastActiveAt,
  isCurrent,
  children,
  deviceType,
}) => {
  const { t } = useTranslation();

  return (
    <Block className={styles.session}>
      <DeviceTypeIcon deviceType={deviceType || DeviceType.Unknown} />
      <div className={styles.container}>
        {isCurrent && (
          <Badge kind="success">{t("frontend.session.current_badge")}</Badge>
        )}
        <H6 className={styles.sessionName} title={id}>
          <Link to="/sessions/$id" params={{ id }}>
            {name || id}
          </Link>
        </H6>
        <SessionMetadata weight="semibold">
          <Trans
            i18nKey="frontend.session.signed_in_date"
            components={{ datetime: <DateTime datetime={createdAt} /> }}
          />
        </SessionMetadata>
        {!!finishedAt && (
          <SessionMetadata weight="semibold" data-finished={true}>
            <Trans
              i18nKey="frontend.session.finished_date"
              components={{ datetime: <DateTime datetime={finishedAt} /> }}
            />
          </SessionMetadata>
        )}
        {!!lastActiveAt && (
          <SessionMetadata>
            <LastActive lastActive={lastActiveAt} />
          </SessionMetadata>
        )}
        {!!lastActiveIp && <SessionMetadata>{lastActiveIp}</SessionMetadata>}
        {!!clientName && (
          <SessionMetadata>
            <ClientAvatar
              size="var(--cpd-space-4x)"
              name={clientName}
              logoUri={clientLogoUri}
            />{" "}
            <SessionMetadata weight="semibold" as="span">
              {clientName}
            </SessionMetadata>
          </SessionMetadata>
        )}
        {!!children && <div className={styles.sessionActions}>{children}</div>}
      </div>
    </Block>
  );
};

export default Session;
