// Copyright 2022-2024 The Matrix.org Foundation C.I.C.
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

import IconChat from "@vector-im/compound-design-tokens/icons/chat.svg?react";
import IconCheckCircle from "@vector-im/compound-design-tokens/icons/check-circle.svg?react";
import IconComputer from "@vector-im/compound-design-tokens/icons/computer.svg?react";
import IconError from "@vector-im/compound-design-tokens/icons/error.svg?react";
import IconInfo from "@vector-im/compound-design-tokens/icons/info.svg?react";
import IconUserProfile from "@vector-im/compound-design-tokens/icons/user-profile.svg?react";
import { Text } from "@vector-im/compound-web";
import { ReactNode } from "react";
import { useTranslation } from "react-i18next";

import Block from "../Block/Block";
import DateTime from "../DateTime";
import LastActive from "../Session/LastActive";

import styles from "./SessionDetails.module.css";

export type Detail = { label: string; value: ReactNode };
type Props = {
  title: string | ReactNode;
  lastActive?: Date;
  signedIn?: Date;
  deviceId?: string;
  ipAddress?: string;
  scopes?: string[];
  details?: Detail[];
};

const Scope: React.FC<{ scope: string }> = ({ scope }) => {
  const { t } = useTranslation();
  // Filter out "urn:matrix:org.matrix.msc2967.client:device:"
  if (scope.startsWith("urn:matrix:org.matrix.msc2967.client:device:")) {
    return null;
  }

  // Needs to be manually kept in sync with /templates/components/scope.html
  const scopeMap: Record<string, [typeof IconInfo, string][]> = {
    openid: [[IconUserProfile, t("mas.scope.view_profile")]],
    "urn:mas:graphql:*": [
      [IconInfo, t("mas.scope.edit_profile")],
      [IconComputer, t("mas.scope.manage_sessions")],
    ],
    "urn:matrix:org.matrix.msc2967.client:api:*": [
      [IconChat, t("mas.scope.view_messages")],
      [IconCheckCircle, t("mas.scope.send_messages")],
    ],
    "urn:synapse:admin:*": [[IconError, t("mas.scope.synapse_admin")]],
    "urn:mas:admin": [[IconError, t("mas.scope.mas_admin")]],
  };

  const mappedScopes: [typeof IconInfo, string][] = scopeMap[scope] ?? [
    [IconInfo, scope],
  ];

  return (
    <>
      {mappedScopes.map(([Icon, text], i) => (
        <li className={styles.scope} key={i}>
          <Icon />
          <Text size="md" weight="medium">
            {text}
          </Text>
        </li>
      ))}
    </>
  );
};

const Datum: React.FC<{ label: string; value: ReactNode }> = ({
  label,
  value,
}) => {
  return (
    <div className={styles.datum}>
      <Text size="sm" weight="regular" as="h5">
        {label}
      </Text>
      {typeof value === "string" ? (
        <Text size="md" className={styles.datumValue}>
          {value}
        </Text>
      ) : (
        value
      )}
    </div>
  );
};

const SessionDetails: React.FC<Props> = ({
  title,
  lastActive,
  signedIn,
  deviceId,
  ipAddress,
  details,
  scopes,
}) => {
  const { t } = useTranslation();

  return (
    <Block title={title}>
      <div className={styles.wrapper}>
        {lastActive && (
          <Datum
            label={t("frontend.session.last_active_label")}
            value={
              <LastActive
                className={styles.datumValue}
                lastActive={lastActive}
              />
            }
          />
        )}
        {signedIn && (
          <Datum
            label={t("frontend.session.signed_in_label")}
            value={
              <DateTime className={styles.datumValue} datetime={signedIn} />
            }
          />
        )}
        {deviceId && (
          <Datum
            label={t("frontend.session.device_id_label")}
            value={deviceId}
          />
        )}
        {ipAddress && (
          <Datum
            label={t("frontend.session.ip_label")}
            value={<code className={styles.datumValue}>{ipAddress}</code>}
          />
        )}
        {details?.map(({ label, value }) => (
          <Datum key={label} label={label} value={value} />
        ))}
      </div>

      {scopes?.length && (
        <Datum
          label={t("frontend.session.scopes_label")}
          value={
            <ul className={styles.scopeList}>
              {scopes.map((scope) => (
                <Scope key={scope} scope={scope} />
              ))}
            </ul>
          }
        />
      )}
    </Block>
  );
};

export default SessionDetails;
