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
import { parseISO, subDays, subHours } from "date-fns";

import LastActive from "./LastActive";

const meta = {
  title: "UI/Session/Last active time",
  component: LastActive,
  argTypes: {
    lastActive: { control: { type: "date" } },
    now: { control: { type: "date" } },
  },
  tags: ["autodocs"],
} satisfies Meta<typeof LastActive>;

export default meta;
type Story = StoryObj<typeof LastActive>;

const now = parseISO("2023-09-18T01:12:00.000Z");

export const Basic: Story = {
  args: {
    // An hour ago
    lastActive: subHours(now, 1),
    now,
  },
};

export const ActiveThreeDaysAgo: Story = {
  args: {
    // Three days ago
    lastActive: subDays(now, 3),
    now,
  },
};

export const ActiveNow: Story = {
  args: {
    lastActive: now,
    now,
  },
};

export const Inactive: Story = {
  args: {
    // 91 days ago
    lastActive: subDays(now, 91),
    now,
  },
};
