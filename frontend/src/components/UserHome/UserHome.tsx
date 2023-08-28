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

import { Alert, Body, H3, H6 } from "@vector-im/compound-web";
import { useState } from "react";

import { Link } from "../../Router";
import { FragmentType, graphql, useFragment } from "../../gql";
import Block from "../Block/Block";
import BlockList from "../BlockList/BlockList";

import styles from "./UserHome.module.css";

export const FRAGMENT = graphql(/* GraphQL */ `
  fragment UserHome_user on User {
    id

    primaryEmail {
      id
      ...UserEmail_email
    }

    confirmedEmails: emails(first: 0, state: CONFIRMED) {
      totalCount
    }

    unverifiedEmails: emails(first: 0, state: PENDING) {
      totalCount
    }

    browserSessions(first: 0, state: ACTIVE) {
      totalCount
    }

    oauth2Sessions(first: 0, state: ACTIVE) {
      totalCount
    }

    compatSessions(first: 0, state: ACTIVE) {
      totalCount
    }
  }
`);

const UserHome: React.FC<{
  user: FragmentType<typeof FRAGMENT>;
}> = ({ user }) => {
  const data = useFragment(FRAGMENT, user);
  const [dismiss, setDismiss] = useState(false);

  const doDismiss = (): void => {
    setDismiss(true);
  };

  // allow this until we get i18n
  const pluraliseSession = (count: number): string =>
    count === 1 ? "session" : "sessions";

  // user friendly description of sessions is:
  // browser -> browser
  // oauth2 sessions -> New apps
  // compatibility sessions -> Regular apps

  return (
    <BlockList>
      {data.unverifiedEmails.totalCount > 0 && !dismiss && (
        <Alert type="critical" title="Unverified email" onClose={doDismiss}>
          You have {data.unverifiedEmails.totalCount} unverified email
          address(es). <Link route={{ type: "profile" }}>Check</Link>
        </Alert>
      )}
      {/* This is a short term solution, so I won't bother extracting these blocks into components */}

      <H3>Where you're signed in</H3>
      <Block className={styles.sessionListBlock}>
        <div className={styles.sessionListBlockInfo}>
          <H6>Browser</H6>
          <Body>
            {data.browserSessions.totalCount} active{" "}
            {pluraliseSession(data.browserSessions.totalCount)}
          </Body>
        </div>
        <Link route={{ type: "browser-session-list" }}>View all</Link>
      </Block>
      <Block className={styles.sessionListBlock}>
        <div className={styles.sessionListBlockInfo}>
          <H6>New apps</H6>
          <Body>
            {data.oauth2Sessions.totalCount} active{" "}
            {pluraliseSession(data.oauth2Sessions.totalCount)}
          </Body>
        </div>
        <Link route={{ type: "oauth2-session-list" }}>View all</Link>
      </Block>
      <Block className={styles.sessionListBlock}>
        <div className={styles.sessionListBlockInfo}>
          <H6>Regular apps</H6>
          <Body>
            {data.compatSessions.totalCount} active{" "}
            {pluraliseSession(data.compatSessions.totalCount)}
          </Body>
        </div>
        <Link route={{ type: "compat-session-list" }}>View all</Link>
      </Block>
    </BlockList>
  );
};

export default UserHome;
