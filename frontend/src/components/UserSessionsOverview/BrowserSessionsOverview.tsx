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

import { Text, H5 } from "@vector-im/compound-web";
import { useTranslation } from "react-i18next";

import { FragmentType, graphql, useFragment } from "../../gql";
import { Link } from "../Link";

import styles from "./BrowserSessionsOverview.module.css";

export const FRAGMENT = graphql(/* GraphQL */ `
  fragment BrowserSessionsOverview_user on User {
    id

    browserSessions(first: 0, state: ACTIVE) {
      totalCount
    }
  }
`);

const BrowserSessionsOverview: React.FC<{
  user: FragmentType<typeof FRAGMENT>;
}> = ({ user }) => {
  const data = useFragment(FRAGMENT, user);
  const { t } = useTranslation();

  return (
    <div className={styles.browserSessionsOverview}>
      <div className="flex flex-1 flex-col">
        <H5>{t("frontend.browser_sessions_overview.heading")}</H5>
        <Text>
          {t("frontend.browser_sessions_overview.body", {
            count: data.browserSessions.totalCount,
          })}
        </Text>
      </div>
      <Link to="/sessions/browsers" search={{ first: 6 }}>
        {t("frontend.browser_sessions_overview.view_all_button")}
      </Link>
    </div>
  );
};

export default BrowserSessionsOverview;
