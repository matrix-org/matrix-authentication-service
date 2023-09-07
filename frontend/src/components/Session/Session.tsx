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

import { H6, Body, Badge } from "@vector-im/compound-web";
import { ReactNode } from "react";

import Block from "../Block";
import DateTime from "../DateTime";

import ClientAvatar from "./ClientAvatar";
import styles from "./Session.module.css";

const SessionMetadata: React.FC<React.ComponentProps<typeof Body>> = (
  props,
) => <Body {...props} size="sm" className={styles.sessionMetadata} />;

export type SessionProps = {
  id: string;
  name?: string | ReactNode;
  createdAt: string;
  finishedAt?: string;
  clientName?: string;
  clientLogoUri?: string;
  isCurrent?: boolean;
};
const Session: React.FC<React.PropsWithChildren<SessionProps>> = ({
  id,
  name,
  createdAt,
  finishedAt,
  clientName,
  clientLogoUri,
  isCurrent,
  children,
}) => {
  return (
    <Block>
      {isCurrent && <Badge kind="success">Current</Badge>}
      <H6 className={styles.sessionName} title={id}>
        {name || id}
      </H6>
      <SessionMetadata weight="semibold">
        Signed in <DateTime datetime={createdAt} />
      </SessionMetadata>
      {!!finishedAt && (
        <SessionMetadata weight="semibold" data-finished={true}>
          Finished <DateTime datetime={finishedAt} />
        </SessionMetadata>
      )}
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
    </Block>
  );
};

export default Session;
