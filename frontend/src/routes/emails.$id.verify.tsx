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

import { createFileRoute } from "@tanstack/react-router";
import { useTranslation } from "react-i18next";
import { useQuery } from "urql";

import GraphQLError from "../components/GraphQLError";
import VerifyEmailComponent from "../components/VerifyEmail";
import { graphql } from "../gql";

export const Route = createFileRoute("/emails/$id/verify")({
  component: EmailVerify,
});

const QUERY = graphql(/* GraphQL */ `
  query VerifyEmailQuery($id: ID!) {
    userEmail(id: $id) {
      ...UserEmail_verifyEmail
    }
  }
`);

function EmailVerify(): React.ReactElement {
  const { id } = Route.useParams();
  const [result] = useQuery({ query: QUERY, variables: { id } });
  const { t } = useTranslation();

  if (result.error) return <GraphQLError error={result.error} />;
  if (!result.data) throw new Error(); // Suspense mode is enabled

  const email = result.data.userEmail;
  if (email == null) return <>{t("frontend.verify_email.unknown_email")}</>;

  return <VerifyEmailComponent email={email} />;
}
