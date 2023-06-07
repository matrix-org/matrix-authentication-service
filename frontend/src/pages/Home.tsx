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

import { Alert } from "@vector-im/compound-web";
import { useAtomValue } from "jotai";

import { currentUserIdAtom } from "../atoms";
import BrowserSessionList from "../components/BrowserSessionList";
import CompatSsoLoginList from "../components/CompatSsoLoginList";
import OAuth2SessionList from "../components/OAuth2SessionList";
import UserGreeting from "../components/UserGreeting";

const Home: React.FC = () => {
  const currentUserId = useAtomValue(currentUserIdAtom);

  if (currentUserId) {
    return (
      <>
        <UserGreeting userId={currentUserId} />
        <div className="mt-4 grid lg:grid-cols-3 gap-1">
          <OAuth2SessionList userId={currentUserId} />
          <CompatSsoLoginList userId={currentUserId} />
          <BrowserSessionList userId={currentUserId} />
        </div>
      </>
    );
  } else {
    return <Alert type="critical" title="You're not logged in." />;
  }
};

export default Home;
