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

import { Heading, Text, Avatar } from "@vector-im/compound-web";

import { FragmentType, graphql, useFragment } from "../gql";

import UnverifiedEmailAlert from "./UnverifiedEmailAlert";
import styles from "./UserGreeting.module.css";

export const USER_GREETING_FRAGMENT = graphql(/* GraphQL */ `
  fragment UserGreeting_user on User {
    id
    username
    matrix {
      mxid
      displayName
    }

    ...UnverifiedEmailAlert
  }
`);

type Props = {
  user: FragmentType<typeof USER_GREETING_FRAGMENT>;
};

const UserGreeting: React.FC<Props> = ({ user }) => {
  const data = useFragment(USER_GREETING_FRAGMENT, user);

  return (
    <>
      <header className={styles.header}>
        <Avatar
          size="var(--cpd-space-24x)"
          id={data.matrix.mxid}
          name={data.matrix.displayName || data.matrix.mxid}
        />
        <Heading size="xl" weight="semibold">
          {data.matrix.displayName || data.username}
        </Heading>
        <Text size="lg" className={styles.mxid}>
          {data.matrix.mxid}
        </Text>
      </header>
      <UnverifiedEmailAlert user={data} />
    </>
  );
};

export default UserGreeting;
