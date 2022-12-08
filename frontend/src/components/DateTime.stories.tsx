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

import type { Meta, StoryObj } from "@storybook/react";
import { sub } from "date-fns";

import DateTime from "./DateTime";

const now = new Date(2022, 11, 16, 15, 32, 10);

const meta = {
  title: "UI/DateTime",
  component: DateTime,
  tags: ["docsPage"],
  args: {
    now,
    datetime: sub(now, { minutes: 30 }),
  },
  argTypes: {
    now: {
      control: "date",
    },
    datetime: {
      control: "date",
    },
  },
} satisfies Meta<typeof DateTime>;

export default meta;
type Story = StoryObj<typeof DateTime>;

export const Basic: Story = {};

export const Now: Story = {
  args: {
    datetime: now,
  },
};

export const SecondsAgo: Story = {
  args: {
    datetime: sub(now, { seconds: 30 }),
  },
};

export const MinutesAgo: Story = {
  args: {
    datetime: sub(now, { minutes: 5 }),
  },
};

export const HoursAgo: Story = {
  args: {
    datetime: sub(now, { hours: 5 }),
  },
};
