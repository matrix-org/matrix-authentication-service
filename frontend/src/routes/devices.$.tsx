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

import { createFileRoute, notFound, redirect } from "@tanstack/react-router";
import { Alert } from "@vector-im/compound-web";
import { useTranslation } from "react-i18next";

import Layout from "../components/Layout";
import { Link } from "../components/Link";
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

export const Route = createFileRoute("/devices/$")({
  async loader({ context, params, abortController: { signal } }) {
    const viewer = await context.client.query(
      CURRENT_VIEWER_QUERY,
      {},
      {
        fetchOptions: { signal },
      },
    );
    if (viewer.error) throw viewer.error;
    if (viewer.data?.viewer.__typename !== "User") throw notFound();

    const result = await context.client.query(
      QUERY,
      {
        deviceId: params._splat || "",
        userId: viewer.data.viewer.id,
      },
      { fetchOptions: { signal } },
    );
    if (result.error) throw result.error;
    const session = result.data?.session;
    if (!session) throw notFound();

    throw redirect({
      to: "/sessions/$id",
      params: { id: session.id },
      replace: true,
    });
  },

  notFoundComponent: NotFound,
});

function NotFound(): React.ReactElement {
  const { t } = useTranslation();
  const { _splat: deviceId } = Route.useParams();
  return (
    <Layout>
      <Alert
        type="critical"
        title={t("frontend.session_detail.alert.title", { deviceId })}
      >
        {t("frontend.session_detail.alert.text")}
        <Link to="/sessions" search={{ first: 6 }}>
          {t("frontend.session_detail.alert.button")}
        </Link>
      </Alert>
    </Layout>
  );
}
