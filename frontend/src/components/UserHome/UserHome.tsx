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

import { Alert, Body } from "@vector-im/compound-web";
import { useState } from "react";

import { Link } from "../../Router";
import { FragmentType, graphql, useFragment } from "../../gql";
import UserEmail from "../UserEmail";

const FRAGMENT = graphql(/* GraphQL */ `
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

  return (
    <>
      {data.unverifiedEmails.totalCount > 0 && !dismiss && (
        <Alert type="critical" title="Unverified email" onClose={doDismiss}>
          You have {data.unverifiedEmails.totalCount} unverified email
          address(es). <Link route={{ type: "email-list" }}>Check</Link>
        </Alert>
      )}

      {data.primaryEmail ? (
        <UserEmail email={data.primaryEmail} isPrimary />
      ) : (
        <Alert type="critical" title="No primary email adress" />
      )}

      {data.confirmedEmails.totalCount > 1 && (
        <Body>
          {data.confirmedEmails.totalCount} additional emails.{" "}
          <Link route={{ type: "email-list" }}>View all</Link>
        </Body>
      )}

      <Body>
        {data.browserSessions.totalCount} active browser session(s).{" "}
        <Link route={{ type: "browser-session-list" }}>View all</Link>
      </Body>
      <Body>
        {data.oauth2Sessions.totalCount} active OAuth2 session(s).{" "}
        <Link route={{ type: "oauth2-session-list" }}>View all</Link>
      </Body>
      <Body>
        {data.compatSessions.totalCount} active compatibility layer session(s).{" "}
        <Link route={{ type: "compat-session-list" }}>View all</Link>
      </Body>
    </>
  );
};

export default UserHome;
