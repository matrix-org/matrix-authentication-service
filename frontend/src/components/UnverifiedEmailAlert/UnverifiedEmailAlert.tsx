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
import { useEffect, useState } from "react";
import { useTranslation } from "react-i18next";

import { FragmentType, useFragment, graphql } from "../../gql";
import { Link } from "../Link";

import styles from "./UnverifiedEmailAlert.module.css";

export const UNVERIFIED_EMAILS_FRAGMENT = graphql(/* GraphQL */ `
  fragment UnverifiedEmailAlert_user on User {
    id
    unverifiedEmails: emails(first: 0, state: PENDING) {
      totalCount
    }
  }
`);

const UnverifiedEmailAlert: React.FC<{
  user?: FragmentType<typeof UNVERIFIED_EMAILS_FRAGMENT>;
}> = ({ user }) => {
  const data = useFragment(UNVERIFIED_EMAILS_FRAGMENT, user);
  const [dismiss, setDismiss] = useState(false);
  const { t } = useTranslation();

  const doDismiss = (): void => setDismiss(true);

  useEffect(() => {
    setDismiss(false);
  }, [data?.unverifiedEmails?.totalCount]);

  if (!data?.unverifiedEmails?.totalCount || dismiss) {
    return null;
  }

  return (
    <Alert
      type="critical"
      title={t("frontend.unverified_email_alert.title")}
      onClose={doDismiss}
      className={styles.alert}
    >
      {t("frontend.unverified_email_alert.text", {
        count: data.unverifiedEmails.totalCount,
      })}{" "}
      <Link to="/" hash="emails">
        {t("frontend.unverified_email_alert.button")}
      </Link>
    </Alert>
  );
};

export default UnverifiedEmailAlert;
