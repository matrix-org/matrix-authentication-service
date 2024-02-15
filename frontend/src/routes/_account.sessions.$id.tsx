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
import { Alert } from "@vector-im/compound-web";
import { useTranslation } from "react-i18next";
import { useQuery } from "urql";

import { Link } from "../components/Link";
import BrowserSessionDetail from "../components/SessionDetail/BrowserSessionDetail";
import CompatSessionDetail from "../components/SessionDetail/CompatSessionDetail";
import OAuth2SessionDetail from "../components/SessionDetail/OAuth2SessionDetail";
import { graphql } from "../gql";

export const Route = createFileRoute("/_account/sessions/$id")({
  async loader({ context, params }) {
    const result = await context.client.query(QUERY, { id: params.id });
    if (result.error) throw result.error;
    if (!result.data?.node) throw notFound();
  },

  notFoundComponent: NotFound,
  component: SessionDetail,
});

const QUERY = graphql(/* GraphQL */ `
  query SessionDetailQuery($id: ID!) {
    node(id: $id) {
      __typename
      ...CompatSession_detail
      ...OAuth2Session_detail
      ...BrowserSession_detail
    }
  }
`);

function NotFound(): React.ReactElement {
  const { id } = Route.useParams();
  const { t } = useTranslation();

  return (
    <Alert
      type="critical"
      title={t("frontend.session_detail.alert.title", { deviceId: id })}
    >
      {t("frontend.session_detail.alert.text")}
      <Link from={Route.fullPath} to="..">
        {t("frontend.session_detail.alert.button")}
      </Link>
    </Alert>
  );
}

function SessionDetail(): React.ReactElement {
  const { id } = Route.useParams();
  const [result] = useQuery({ query: QUERY, variables: { id } });
  if (result.error) throw result.error;
  const node = result.data?.node;
  if (!node) throw notFound();

  switch (node.__typename) {
    case "CompatSession":
      return <CompatSessionDetail session={node} />;
    case "Oauth2Session":
      return <OAuth2SessionDetail session={node} />;
    case "BrowserSession":
      return <BrowserSessionDetail session={node} />;
    default:
      throw new Error("Unknown session type");
  }
}
