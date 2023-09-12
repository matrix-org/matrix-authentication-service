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

import { Body, H3, H6 } from "@vector-im/compound-web";

import { FragmentType, graphql, useFragment } from "../../gql";
import { Link } from "../../routing";
import Block from "../Block";
import BlockList from "../BlockList";

import CombinedSessionsList from "./CombinedSessionsList";
import styles from "./UserSessionsOverview.module.css";

export const FRAGMENT = graphql(/* GraphQL */ `
  fragment UserSessionsOverview_user on User {
    id

    primaryEmail {
      id
      ...UserEmail_email
    }

    confirmedEmails: emails(first: 0, state: CONFIRMED) {
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

const UserSessionsOverview: React.FC<{
  user: FragmentType<typeof FRAGMENT>;
}> = ({ user }) => {
  const data = useFragment(FRAGMENT, user);

  // allow this until we get i18n
  const pluraliseSession = (count: number): string =>
    count === 1 ? "session" : "sessions";

  // user friendly description of sessions is:
  // browser -> browser
  // oauth2 sessions -> New apps
  // compatibility sessions -> Regular apps

  return (
    <BlockList>
      <CombinedSessionsList userId={data.id} />
    </BlockList>
  );
};

export default UserSessionsOverview;
