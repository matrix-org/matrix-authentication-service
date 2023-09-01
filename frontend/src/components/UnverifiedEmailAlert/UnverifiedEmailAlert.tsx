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

import { Alert } from "@vector-im/compound-web";
import { useState } from "react";

import { FragmentType, useFragment, graphql } from "../../gql";
import { Link } from "../../routing";

import styles from "./UnverifiedEmailAlert.module.css";

export const UNVERIFIED_EMAILS_FRAGMENT = graphql(/* GraphQL */ `
  fragment UnverifiedEmailAlert on User {
    id
    unverifiedEmails: emails(first: 0, state: PENDING) {
      totalCount
    }
  }
`);

const UnverifiedEmailAlert: React.FC<{
  unverifiedEmails?: FragmentType<typeof UNVERIFIED_EMAILS_FRAGMENT>;
}> = ({ unverifiedEmails }) => {
  const data = useFragment(UNVERIFIED_EMAILS_FRAGMENT, unverifiedEmails);
  const [dismiss, setDismiss] = useState(false);

  const doDismiss = (): void => setDismiss(true);

  if (!data?.unverifiedEmails?.totalCount || dismiss) {
    return null;
  }

  return (
    <Alert
      type="critical"
      title="Unverified email"
      onClose={doDismiss}
      className={styles.alert}
    >
      You have {data.unverifiedEmails.totalCount} unverified email address(es).{" "}
      <Link kind="button" route={{ type: "profile" }}>
        Review and verify
      </Link>
    </Alert>
  );
};

export default UnverifiedEmailAlert;
