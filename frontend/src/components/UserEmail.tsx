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

import { FragmentType, graphql, useFragment } from "../gql";
import React from "react";
import Block from "./Block";
import Typography, { Bold } from "./Typography";
import DateTime from "./DateTime";

const FRAGMENT = graphql(/* GraphQL */ `
  fragment UserEmail_email on UserEmail {
    id
    email
    createdAt
    confirmedAt
  }
`);

const UserEmail: React.FC<{ email: FragmentType<typeof FRAGMENT> }> = ({
  email,
}) => {
  const data = useFragment(FRAGMENT, email);
  return (
    <Block>
      <Typography variant="caption">
        <Bold>{data.email}</Bold>
        {data.confirmedAt ? "" : " (not verified)"}
      </Typography>
      {data.confirmedAt ? (
        <Typography variant="micro">
          Verified <DateTime datetime={data.confirmedAt} />
        </Typography>
      ) : (
        <Typography variant="micro">
          Added <DateTime datetime={data.createdAt} />
        </Typography>
      )}
    </Block>
  );
};

export default UserEmail;
