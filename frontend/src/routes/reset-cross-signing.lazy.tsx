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

import { createLazyFileRoute, notFound } from "@tanstack/react-router";
import IconArrowLeft from "@vector-im/compound-design-tokens/assets/web/icons/arrow-left";
import IconKey from "@vector-im/compound-design-tokens/assets/web/icons/key";
import { Alert, Button, Text } from "@vector-im/compound-web";
import { useTranslation } from "react-i18next";
import { useMutation, useQuery } from "urql";

import BlockList from "../components/BlockList";
import { ButtonLink } from "../components/ButtonLink";
import Layout from "../components/Layout";
import LoadingSpinner from "../components/LoadingSpinner";
import PageHeading from "../components/PageHeading";
import { graphql } from "../gql";

import { CURRENT_VIEWER_QUERY } from "./reset-cross-signing";

const ALLOW_CROSS_SIGING_RESET_MUTATION = graphql(/* GraphQL */ `
  mutation AllowCrossSigningReset($userId: ID!) {
    allowUserCrossSigningReset(input: { userId: $userId }) {
      user {
        id
      }
    }
  }
`);

export const Route = createLazyFileRoute("/reset-cross-signing")({
  component: ResetCrossSigning,
});

function ResetCrossSigning(): React.ReactNode {
  const { deepLink } = Route.useSearch();
  const { t } = useTranslation();
  const [viewer] = useQuery({ query: CURRENT_VIEWER_QUERY });
  if (viewer.error) throw viewer.error;
  if (viewer.data?.viewer.__typename !== "User") throw notFound();
  const userId = viewer.data.viewer.id;

  const [result, allowReset] = useMutation(ALLOW_CROSS_SIGING_RESET_MUTATION);

  const onClick = (): void => {
    allowReset({ userId });
  };

  return (
    <Layout>
      <BlockList>
        <PageHeading
          Icon={IconKey}
          title={t("frontend.reset_cross_signing.heading")}
          invalid
        />

        {!result.data && !result.error && (
          <>
            <Text className="text-justify">
              {t("frontend.reset_cross_signing.description")}
            </Text>
            <Button
              kind="primary"
              destructive
              disabled={result.fetching}
              onClick={onClick}
            >
              {!!result.fetching && <LoadingSpinner inline />}
              {t("frontend.reset_cross_signing.button")}
            </Button>
          </>
        )}
        {result.data && (
          <Alert
            type="info"
            title={t("frontend.reset_cross_signing.success.title")}
          >
            {t("frontend.reset_cross_signing.success.description")}
          </Alert>
        )}
        {result.error && (
          <Alert
            type="critical"
            title={t("frontend.reset_cross_signing.failure.title")}
          >
            {t("frontend.reset_cross_signing.failure.description")}
          </Alert>
        )}

        {!deepLink && (
          <ButtonLink to="/" kind="tertiary" Icon={IconArrowLeft}>
            {t("action.back")}
          </ButtonLink>
        )}
      </BlockList>
    </Layout>
  );
}
