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

import { Alert, Button, H3, Text } from "@vector-im/compound-web";
import { useTranslation } from "react-i18next";
import { useMutation } from "urql";

import { graphql } from "../../gql";
import BlockList from "../BlockList";
import LoadingSpinner from "../LoadingSpinner";

const ALLOW_CROSS_SIGING_RESET_MUTATION = graphql(/* GraphQL */ `
  mutation AllowCrossSigningReset($userId: ID!) {
    allowUserCrossSigningReset(input: { userId: $userId }) {
      user {
        id
      }
    }
  }
`);

const CrossSigningReset: React.FC<{ userId: string }> = ({ userId }) => {
  const { t } = useTranslation();
  const [result, allowReset] = useMutation(ALLOW_CROSS_SIGING_RESET_MUTATION);

  const onClick = (): void => {
    allowReset({ userId });
  };

  return (
    <BlockList>
      <H3>{t("frontend.reset_cross_signing.heading")}</H3>
      {!result.data && !result.error && (
        <>
          <Text className="text-justify">
            {t("frontend.reset_cross_signing.description")}
          </Text>
          <Button
            kind="destructive"
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
    </BlockList>
  );
};

export default CrossSigningReset;
