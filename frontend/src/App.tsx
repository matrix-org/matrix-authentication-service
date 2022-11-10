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

import React from "react";
import { graphql, useLazyLoadQuery } from "react-relay";

import type { AppQuery } from "./__generated__/AppQuery.graphql";

export const App: React.FC = () => {
  const data = useLazyLoadQuery<AppQuery>(
    graphql`
      query AppQuery {
        currentUser {
          id
          username
        }
      }
    `,
    {}
  );

  if (data.currentUser) {
    return (
      <h1 className="font-bold text-2xl">Hello {data.currentUser.username}!</h1>
    );
  } else {
    return <div className="font-bold text-alert">You're not logged in.</div>;
  }
};
