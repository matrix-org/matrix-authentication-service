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

import { currentUserIdAtom } from "../atoms";
import BrowserSessionList from "../components/BrowserSessionList";
import CompatSessionList from "../components/CompatSessionList";
import GraphQLError from "../components/GraphQLError";
import NotLoggedIn from "../components/NotLoggedIn";
import OAuth2SessionList from "../components/OAuth2SessionList";
import UserGreeting from "../components/UserGreeting";
import { isErr, unwrapErr, unwrapOk } from "../result";

const Home: React.FC = () => {
  const result = useAtomValue(currentUserIdAtom);
  if (isErr(result)) return <GraphQLError error={unwrapErr(result)} />;

  const currentUserId = unwrapOk(result);
  if (currentUserId === null) return <NotLoggedIn />;

  return (
    <>
      <UserGreeting userId={currentUserId} />
      <div className="mt-4 grid gap-8">
        <OAuth2SessionList userId={currentUserId} />
        <CompatSessionList userId={currentUserId} />
        <BrowserSessionList userId={currentUserId} />
      </div>
    </>
  );
};

export default Home;
