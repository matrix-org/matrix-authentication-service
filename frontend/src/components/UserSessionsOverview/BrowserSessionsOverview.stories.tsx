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

import type { Meta, StoryObj } from "@storybook/react";

import { makeFragmentData } from "../../gql";
import { DummyRouter } from "../../test-utils/router";

import BrowserSessionsOverview, { FRAGMENT } from "./BrowserSessionsOverview";

type Props = {
  browserSessions: number;
};

const Template: React.FC<Props> = ({ browserSessions }) => {
  const data = makeFragmentData(
    {
      id: "user:123",
      browserSessions: {
        totalCount: browserSessions,
      },
    },
    FRAGMENT,
  );
  return (
    <DummyRouter>
      <BrowserSessionsOverview user={data} />
    </DummyRouter>
  );
};

const meta = {
  title: "Pages/User Sessions Overview/Browser Sessions",
  component: Template,
  tags: ["autodocs"],
} satisfies Meta<typeof Template>;

export default meta;
type Story = StoryObj<typeof Template>;

export const Basic: Story = {
  args: {
    browserSessions: 2,
  },
};

export const Empty: Story = {
  args: {
    browserSessions: 0,
  },
};
