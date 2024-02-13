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

import { H3 } from "@vector-im/compound-web";
import { Suspense } from "react";
import { useTranslation } from "react-i18next";

import { FragmentType, useFragment } from "../../gql";
import BlockList from "../BlockList";
import LoadingSpinner from "../LoadingSpinner";

import AppSessionsList from "./AppSessionsList";
import BrowserSessionsOverview, { FRAGMENT } from "./BrowserSessionsOverview";

const UserSessionsOverview: React.FC<{
  user: FragmentType<typeof FRAGMENT>;
}> = ({ user }) => {
  const data = useFragment(FRAGMENT, user);
  const { t } = useTranslation();

  return (
    <BlockList>
      <H3>{t("frontend.user_sessions_overview.heading")}</H3>
      <BrowserSessionsOverview user={user} />
      <Suspense fallback={<LoadingSpinner />}>
        <AppSessionsList userId={data.id} />
      </Suspense>
    </BlockList>
  );
};

export default UserSessionsOverview;
