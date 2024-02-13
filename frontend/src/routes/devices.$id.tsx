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

import { Navigate, createFileRoute } from "@tanstack/react-router";
import { Alert } from "@vector-im/compound-web";
import { useTranslation } from "react-i18next";
import { useQuery } from "urql";

import { graphql } from "../gql";
import { Link } from "../routing";

export const Route = createFileRoute("/devices/$id")({
  loader: ({ context }) => context.userId,
  component: DeviceRedirect,
});

const QUERY = graphql(/* GraphQL */ `
  query DeviceRedirectQuery($deviceId: String!, $userId: ID!) {
    session(deviceId: $deviceId, userId: $userId) {
      __typename
      ... on Node {
        id
      }
    }
  }
`);

function DeviceRedirect(): React.ReactElement {
  const userId = Route.useLoaderData();
  const { t } = useTranslation();
  const { id: deviceId } = Route.useParams();
  const [result] = useQuery({
    query: QUERY,
    variables: { deviceId, userId },
  });
  if (result.error) throw result.error;
  if (!result.data) throw new Error(); // Suspense mode is enabled

  const session = result.data.session;
  if (!session) {
    return (
      <Alert
        type="critical"
        title={t("frontend.session_detail.alert.title", { deviceId })}
      >
        {t("frontend.session_detail.alert.text")}
        <Link to="/sessions">{t("frontend.session_detail.alert.button")}</Link>
      </Alert>
    );
  }

  return <Navigate to="/sessions/$id" params={{ id: session.id }} replace />;
}
