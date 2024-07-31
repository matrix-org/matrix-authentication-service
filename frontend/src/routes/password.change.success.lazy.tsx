// Copyright 2024 The Matrix.org Foundation C.I.C.
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

import { createLazyFileRoute } from "@tanstack/react-router";
import IconCheckCircle from "@vector-im/compound-design-tokens/assets/web/icons/check-circle-solid";
import { useTranslation } from "react-i18next";

import BlockList from "../components/BlockList";
import { ButtonLink } from "../components/ButtonLink";
import Layout from "../components/Layout";
import PageHeading from "../components/PageHeading";

export const Route = createLazyFileRoute("/password/change/success")({
  component: ChangePasswordSuccess,
});

function ChangePasswordSuccess(): React.ReactNode {
  const { t } = useTranslation();

  return (
    <Layout>
      <BlockList>
        <PageHeading
          Icon={IconCheckCircle}
          title={t("frontend.password_change.success.title")}
          subtitle={t("frontend.password_change.success.description")}
          success
        />

        <ButtonLink to="/" kind="tertiary">
          {t("action.back")}
        </ButtonLink>
      </BlockList>
    </Layout>
  );
}
