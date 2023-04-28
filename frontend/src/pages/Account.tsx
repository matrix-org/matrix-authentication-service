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

import { useAtomValue } from "jotai";

import { currentUserIdAtom } from "../atoms";
import AddEmailForm, { addUserEmailAtom } from "../components/AddEmailForm";
import UserEmailList from "../components/UserEmailList";
import UserGreeting from "../components/UserGreeting";

const UserAccount: React.FC<{ id: string }> = ({ id }) => {
  const addUserEmail = useAtomValue(addUserEmailAtom);
  return (
    <div className="grid grid-cols-1 gap-4">
      <UserGreeting userId={id} />
      <UserEmailList
        userId={id}
        highlightedEmail={addUserEmail.data?.addEmail?.email?.id}
      />
      <AddEmailForm userId={id} />
    </div>
  );
};

const CurrentUserAccount: React.FC = () => {
  const userId = useAtomValue(currentUserIdAtom);
  if (userId !== null) {
    return (
      <div className="w-96 mx-auto">
        <UserAccount id={userId} />
      </div>
    );
  }

  return <div className="w-96 mx-auto">Not logged in.</div>;
};

export default CurrentUserAccount;
