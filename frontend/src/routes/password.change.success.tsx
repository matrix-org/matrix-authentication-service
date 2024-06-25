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

import { createFileRoute, notFound } from "@tanstack/react-router";
import IconLockSolid from "@vector-im/compound-design-tokens/icons/lock-solid.svg?react";
import { Alert } from "@vector-im/compound-web";
import { useTranslation } from "react-i18next";
import { useQuery } from "urql";

import BlockList from "../components/BlockList";
import { ButtonLink } from "../components/ButtonLink";
import Layout from "../components/Layout";
import PageHeading from "../components/PageHeading";
import { graphql } from "../gql";

const CURRENT_VIEWER_QUERY = graphql(/* GraphQL */ `
  query CurrentViewerQuery {
    viewer {
      __typename
      ... on Node {
        id
      }
    }
  }
`);

export const Route = createFileRoute("/password/change/success")({
  async loader({ context, abortController: { signal } }) {
    const viewer = await context.client.query(
      CURRENT_VIEWER_QUERY,
      {},
      { fetchOptions: { signal } },
    );
    if (viewer.error) throw viewer.error;
    if (viewer.data?.viewer.__typename !== "User") throw notFound();
  },

  component: ChangePasswordSuccess,
});

function ChangePasswordSuccess(): React.ReactNode {
  const { t } = useTranslation();
  const [viewer] = useQuery({ query: CURRENT_VIEWER_QUERY });
  if (viewer.error) throw viewer.error;
  if (viewer.data?.viewer.__typename !== "User") throw notFound();

  return (
    <Layout>
      <BlockList>
        <PageHeading
          Icon={IconLockSolid}
          title={t("frontend.password_change.title")}
          subtitle={t("frontend.password_change.subtitle")}
          success
        />

        <Alert
          type="success"
          title={t("frontend.password_change.success.title")}
        >
          {t("frontend.password_change.success.description")}
        </Alert>

        <ButtonLink to="/" kind="tertiary">
          {t("action.back")}
        </ButtonLink>
      </BlockList>
    </Layout>
  );
}
