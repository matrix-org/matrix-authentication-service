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

import { Meta, StoryObj } from "@storybook/react";

import { DummyRouter } from "../../test-utils/router";

import { Filter } from "./Filter";

const meta = {
  title: "UI/Filter",
  component: Filter,
  tags: ["autodocs"],
  args: {
    children: "Filter",
    enabled: false,
  },
  decorators: [
    (Story): React.ReactElement => (
      <DummyRouter>
        <div className="flex gap-4">
          <Story />
        </div>
      </DummyRouter>
    ),
  ],
} satisfies Meta<typeof Filter>;

export default meta;
type Story = StoryObj<typeof meta>;

export const Disabled: Story = {
  args: {
    enabled: false,
  },
};

export const Enabled: Story = {
  args: {
    enabled: true,
  },
};
