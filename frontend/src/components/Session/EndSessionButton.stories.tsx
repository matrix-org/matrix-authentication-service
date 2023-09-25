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

import EndSessionButton from "./EndSessionButton";

const endSessionWithMockAsync = async (): Promise<void> => {
  console.log("End session submitted");
  await new Promise((resolve) => setTimeout(resolve, 1000));
  console.log("End session complete");
};

const meta = {
  title: "UI/Session/End session button",
  component: EndSessionButton,
  tags: ["autodocs"],
  args: {
    endSession: endSessionWithMockAsync,
    sessionCount: undefined,
  },
  argTypes: {
    endSession: { action: "end session confirmed!" },
    sessionCount: {
      control: "number",
    },
  },
} satisfies Meta<typeof EndSessionButton>;

export default meta;
type Story = StoryObj<typeof EndSessionButton>;

export const Basic: Story = {};

export const MultipleSessions: Story = {
  args: {
    sessionCount: 3,
  },
};
