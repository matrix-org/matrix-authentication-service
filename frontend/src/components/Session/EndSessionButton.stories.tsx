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

import { action } from "@storybook/addon-actions";
import type { Meta, StoryObj } from "@storybook/react";

import EndSessionButton from "./EndSessionButton";

const endSession = action("end-session");

const meta = {
  title: "UI/Session/End Session Button",
  component: EndSessionButton,
  tags: ["autodocs"],
  args: {
    endSession: async (): Promise<void> => {
      await new Promise((resolve) => setTimeout(resolve, 300));
      endSession();
    },
  },
  argTypes: {
    children: { control: "text" },
  },
} satisfies Meta<typeof EndSessionButton>;

export default meta;
type Story = StoryObj<typeof EndSessionButton>;

export const Basic: Story = {};

export const WithChildren: Story = {
  args: {
    children:
      "Lorem ipsum dolor sit amet, officia excepteur ex fugiat reprehenderit enim labore culpa sint ad nisi Lorem pariatur mollit ex esse exercitation amet. Nisi anim cupidatat excepteur officia. Reprehenderit nostrud nostrud ipsum Lorem est aliquip amet voluptate voluptate dolor minim nulla est proident. Nostrud officia pariatur ut officia. Sit irure elit esse ea nulla sunt ex occaecat reprehenderit commodo officia dolor Lorem duis laboris cupidatat officia voluptate. Culpa proident adipisicing id nulla nisi laboris ex in Lorem sunt duis officia eiusmod. Aliqua reprehenderit commodo ex non excepteur duis sunt velit enim. Voluptate laboris sint cupidatat ullamco ut ea consectetur et est culpa et culpa duis.",
  },
};
