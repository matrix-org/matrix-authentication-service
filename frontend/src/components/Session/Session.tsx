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

import classNames from "classnames";
import React from "react";

import Block from "../Block";
import DateTime from "../DateTime";
import Typography, { Body, Bold, Code } from "../Typography";

import styles from "./Session.module.css";

const SessionMetadata: React.FC<React.PropsWithChildren<{ bold?: boolean}>> = (props) => <Typography { ...props } variant="caption" className={styles.sessionMetadata}/>

export type SessionProps = {
    id: string;
    name: string;
    createdAt: number;
    finishedAt?: number;
    clientName?: string;
}
const Session: React.FC<SessionProps> = ({
  id, name, createdAt, finishedAt, clientName,
}) => {
  return (
    <Block>
      <Typography variant="subtitle" bold className={styles.sessionName} title={id}>
        { name || id }
      </Typography>
      
      <SessionMetadata bold>
        Signed in <DateTime datetime={createdAt} />
      </SessionMetadata>
      {!!finishedAt && (
        // <p className="text-alert font-semibold">
        //   Finished <DateTime datetime={finishedAt} />
        // </p>
        <SessionMetadata bold data-finished={true}>
            Finished <DateTime datetime={finishedAt} />
        </SessionMetadata>
      )}
      { clientName && <SessionMetadata>
        Client: <Bold>{ clientName }</Bold>
      </SessionMetadata>}
    </Block>
  );
};

export default Session;
