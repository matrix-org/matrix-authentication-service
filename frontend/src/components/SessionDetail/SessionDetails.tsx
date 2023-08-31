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

import { H6, Body } from "@vector-im/compound-web";
import { ReactNode } from "react";

import Block from "../Block/Block";

import styles from "./SessionDetails.module.css";

type Detail = { label: string; value: string | ReactNode };
type Props = {
  title: string;
  details: Detail[];
};

const DetailRow: React.FC<Detail> = ({ label, value }) => (
  <li className={styles.detailRow}>
    <Body size="sm" weight="semibold" className={styles.detailLabel}>
      {label}
    </Body>
    <Body className={styles.detailValue} size="sm">
      {value}
    </Body>
  </li>
);

const SessionDetails: React.FC<Props> = ({ title, details }) => {
  return (
    <Block>
      <H6>{title}</H6>
      <ul className={styles.list}>
        {details.map(({ label, value }) => (
          <DetailRow key={label} label={label} value={value} />
        ))}
      </ul>
    </Block>
  );
};

export default SessionDetails;
