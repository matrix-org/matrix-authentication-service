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

import type { Meta, StoryObj } from "@storybook/react";
import { Provider } from "urql";
import { fromValue, delay, pipe } from "wonka";

import { makeFragmentData } from "../../gql";
import {
  SetDisplayNameMutation,
  SetDisplayNameStatus,
} from "../../gql/graphql";

import UserGreeting, { FRAGMENT } from "./UserGreeting";

const Template: React.FC<{
  displayName?: string;
  mxid: string;
}> = ({ displayName, mxid }) => {
  const userId = "user id";

  const mockClient = {
    /* This will resolve after a small delay */
    executeMutation: () =>
      pipe(
        fromValue({
          data: {
            setDisplayName: {
              status: SetDisplayNameStatus.Set,
              user: { id: userId, matrix: { displayName } },
            },
          },
        } satisfies { data: SetDisplayNameMutation }),
        delay(300),
      ),
  };

  const user = makeFragmentData(
    {
      id: "user id",
      matrix: {
        mxid,
        displayName,
      },
    },
    FRAGMENT,
  );

  return (
    <Provider value={mockClient}>
      <UserGreeting user={user} />
    </Provider>
  );
};

const meta = {
  title: "UI/User Greeting",
  component: Template,
  args: {
    displayName: "Kilgore Trout",
    mxid: "@kilgore:matrix.org",
  },
  argTypes: {
    displayName: {
      control: "text",
    },
    mxid: {
      control: "text",
    },
  },
} satisfies Meta<typeof Template>;

export default meta;
type Story = StoryObj<typeof Template>;

export const Basic: Story = {};

export const NoDisplayName: Story = {
  args: {
    displayName: undefined,
  },
};
