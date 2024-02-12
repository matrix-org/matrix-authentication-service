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
import { useTranslation } from "react-i18next";
import { useQuery } from "urql";

import { graphql } from "../gql";

import UnverifiedEmailAlert from "./UnverifiedEmailAlert";
import styles from "./UserGreeting.module.css";

const QUERY = graphql(/* GraphQL */ `
  query UserGreeting($userId: ID!) {
    user(id: $userId) {
      id
      username
      matrix {
        mxid
        displayName
      }

      ...UnverifiedEmailAlert
    }
  }
`);

const UserGreeting: React.FC<{ userId: string }> = ({ userId }) => {
  const [result] = useQuery({ query: QUERY, variables: { userId } });
  const { t } = useTranslation();

  if (result.data?.user) {
    const user = result.data.user;
    return (
      <>
        <header className={styles.header}>
          <Avatar
            size="var(--cpd-space-24x)"
            id={user.matrix.mxid}
            name={user.matrix.displayName || user.matrix.mxid}
          />
          <Heading size="xl" weight="semibold">
            {user.matrix.displayName || user.username}
          </Heading>
          <Text size="lg" className={styles.mxid}>
            {user.matrix.mxid}
          </Text>
        </header>
        <UnverifiedEmailAlert user={user} />
      </>
    );
  }

  return <>{t("frontend.user_greeting.error")}</>;
};

export default UserGreeting;
