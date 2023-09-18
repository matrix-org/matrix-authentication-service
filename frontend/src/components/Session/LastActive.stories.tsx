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

import LastActive from "./LastActive";

type Props = {
  lastActiveTimestamp: number;
  now: number;
};
const Template: React.FC<Props> = ({ lastActiveTimestamp, now }) => {
  return <LastActive lastActiveTimestamp={lastActiveTimestamp} now={now} />;
};

const meta = {
  title: "UI/Session/Last active time",
  component: Template,
  tags: ["autodocs"],
} satisfies Meta<typeof Template>;

export default meta;
type Story = StoryObj<typeof Template>;

const now = 1694999531800;
const ONE_DAY_MS = 24 * 60 * 60 * 1000;

export const Basic: Story = {
  args: {
    // yesterday
    lastActiveTimestamp: now - ONE_DAY_MS,
    now,
  },
};

export const ActiveNow: Story = {
  args: {
    lastActiveTimestamp: now - 1000,
    now,
  },
};

export const Inactive: Story = {
  args: {
    // yesterday
    lastActiveTimestamp: now - 91 * ONE_DAY_MS,
    now,
  },
};
