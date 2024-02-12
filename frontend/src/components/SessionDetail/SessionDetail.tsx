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

import { Alert } from "@vector-im/compound-web";
import { useTranslation } from "react-i18next";
import { useQuery } from "urql";

import { graphql } from "../../gql";
import { Link } from "../../routing";

import CompatSessionDetail from "./CompatSessionDetail";
import OAuth2SessionDetail from "./OAuth2SessionDetail";

const QUERY = graphql(/* GraphQL */ `
  query SessionQuery($userId: ID!, $deviceId: String!) {
    session(userId: $userId, deviceId: $deviceId) {
      __typename
      ...CompatSession_detail
      ...OAuth2Session_detail
    }
  }
`);

// A type-safe way to ensure we've handled all session types
const unknownSessionType = (type: never): never => {
  throw new Error(`Unknown session type: ${type}`);
};

const SessionDetail: React.FC<{
  deviceId: string;
  userId: string;
}> = ({ deviceId, userId }) => {
  const [result] = useQuery({ query: QUERY, variables: { deviceId, userId } });
  const { t } = useTranslation();

  const session = result.data?.session;

  if (!session) {
    return (
      <Alert
        type="critical"
        title={t("frontend.session_detail.alert.title", { deviceId })}
      >
        {t("frontend.session_detail.alert.text")}
        <Link kind="button" route={{ type: "sessions-overview" }}>
          {t("frontend.session_detail.alert.button")}
        </Link>
      </Alert>
    );
  }

  const sessionType = session.__typename;

  switch (sessionType) {
    case "CompatSession":
      return <CompatSessionDetail session={session} />;
    case "Oauth2Session":
      return <OAuth2SessionDetail session={session} />;
    default:
      unknownSessionType(sessionType);
  }
};

export default SessionDetail;
