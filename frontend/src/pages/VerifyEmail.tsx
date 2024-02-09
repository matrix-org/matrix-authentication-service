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

import { useTranslation } from "react-i18next";
import { useQuery } from "urql";

import ErrorBoundary from "../components/ErrorBoundary";
import GraphQLError from "../components/GraphQLError";
import VerifyEmailComponent from "../components/VerifyEmail";
import { graphql } from "../gql";

const QUERY = graphql(/* GraphQL */ `
  query VerifyEmailQuery($id: ID!) {
    userEmail(id: $id) {
      ...UserEmail_verifyEmail
    }
  }
`);

const VerifyEmail: React.FC<{ id: string }> = ({ id }) => {
  const [result] = useQuery({ query: QUERY, variables: { id } });
  const { t } = useTranslation();

  if (result.error) return <GraphQLError error={result.error} />;
  if (!result.data) throw new Error(); // Suspense mode is enabled

  const email = result.data.userEmail;
  if (email == null) return <>{t("frontend.verify_email.unknown_email")}</>;

  return (
    <ErrorBoundary>
      <VerifyEmailComponent email={email} />
    </ErrorBoundary>
  );
};

export default VerifyEmail;
