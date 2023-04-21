// Copyright 2022 The Matrix.org Foundation C.I.C.
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

import { useAtomValue } from "jotai";
import { atomWithQuery } from "jotai-urql";

import BrowserSessionList from "../components/BrowserSessionList";
import CompatSsoLoginList from "../components/CompatSsoLoginList";
import OAuth2SessionList from "../components/OAuth2SessionList";
import Typography from "../components/Typography";
import { graphql } from "../gql";

const QUERY = graphql(/* GraphQL */ `
  query HomeQuery($count: Int!, $cursor: String) {
    # eslint-disable-next-line @graphql-eslint/no-deprecated
    currentBrowserSession {
      id
      user {
        id
        username

        ...CompatSsoLoginList_user
        ...BrowserSessionList_user
        ...OAuth2SessionList_user
      }
    }
  }
`);

const homeDataAtom = atomWithQuery({
  query: QUERY,
  getVariables: () => ({ count: 10 }),
});

const Home: React.FC = () => {
  const result = useAtomValue(homeDataAtom);

  if (result.error) {
    throw result.error;
  }

  const data = result.data!!;

  if (data.currentBrowserSession) {
    const session = data.currentBrowserSession;
    const user = session.user;

    return (
      <>
        <Typography variant="headline">Hello {user.username}!</Typography>
        <div className="mt-4 grid lg:grid-cols-3 gap-1">
          <OAuth2SessionList user={user} />
          <CompatSsoLoginList user={user} />
          <BrowserSessionList user={user} currentSessionId={session.id} />
        </div>
      </>
    );
  } else {
    return <div className="font-bold text-alert">You're not logged in.</div>;
  }
};

export default Home;
