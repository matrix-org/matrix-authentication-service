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
import { useRef } from "react";

import { Link } from "../../Router";
import { graphql } from "../../gql/gql";
import CompatSession from "../CompatSession";
import OAuth2Session from "../OAuth2Session";

const QUERY = graphql(/* GraphQL */ `
  query SessionQuery($userId: ID!, $deviceId: String!) {
    session(userId: $userId, deviceId: $deviceId) {
      __typename
      ...CompatSession_session
      ...OAuth2Session_session
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

const SessionDetail: React.FC<{
  deviceId: string;
  userId: string;
}> = ({ deviceId, userId }) => {
  const props = useRef({ userId, deviceId });
  const result = useAtomValue(sessionFamily(props.current));

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

  if (sessionType === "Oauth2Session") {
    return <OAuth2Session session={session} />;
  } else {
    return <CompatSession session={session} />;
  }
};

export default SessionDetail;
