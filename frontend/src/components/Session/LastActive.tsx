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

import { differenceInSeconds, parseISO } from "date-fns";

import { formatDate, formatReadableDate } from "../DateTime";

import styles from "./LastActive.module.css";

// 3 minutes
const ACTIVE_NOW_MAX_AGE = 60 * 3;
/// 90 days
const INACTIVE_MIN_AGE = 60 * 60 * 24 * 90;

const LastActive: React.FC<{
  lastActive: Date | string;
  now?: Date | string;
}> = ({ lastActive: lastActiveProps, now: nowProps }) => {
  const lastActive =
    typeof lastActiveProps === "string"
      ? parseISO(lastActiveProps)
      : lastActiveProps;

  const now = nowProps
    ? typeof nowProps === "string"
      ? parseISO(nowProps)
      : nowProps
    : new Date();

  const formattedDate = formatDate(lastActive);
  if (differenceInSeconds(now, lastActive) <= ACTIVE_NOW_MAX_AGE) {
    return (
      <span title={formattedDate} className={styles.active}>
        Active now
      </span>
    );
  }
  if (differenceInSeconds(now, lastActive) > INACTIVE_MIN_AGE) {
    return <span title={formattedDate}>Inactive for 90+ days</span>;
  }
  const relativeDate = formatReadableDate(lastActive, now);
  return <span title={formattedDate}>{`Active ${relativeDate}`}</span>;
};

export default LastActive;
