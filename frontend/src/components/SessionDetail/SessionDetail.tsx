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
import { useAtomValue } from "jotai";
import { atomFamily } from "jotai/utils";
import { atomWithQuery } from "jotai-urql";
import { useMemo } from "react";

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

const sessionFamily = atomFamily(
  ({ userId, deviceId }: { userId: string; deviceId: string }) => {
    const sessionQueryAtom = atomWithQuery({
      query: QUERY,
      getVariables: () => ({ userId, deviceId }),
    });

    return sessionQueryAtom;
  },
);

// A type-safe way to ensure we've handled all session types
const unknownSessionType = (type: never): never => {
  throw new Error(`Unknown session type: ${type}`);
};

const SessionDetail: React.FC<{
  deviceId: string;
  userId: string;
}> = ({ deviceId, userId }) => {
  const sessionFamilyAtomWithProps = useMemo(
    () => sessionFamily({ deviceId, userId }),
    [deviceId, userId],
  );
  const result = useAtomValue(sessionFamilyAtomWithProps);

  const session = result.data?.session;

  if (!session) {
    return (
      <Alert type="critical" title={`Cannot find session: ${deviceId}`}>
        This session does not exist, or is no longer active.
        <Link kind="button" route={{ type: "sessions-overview" }}>
          Go back
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
