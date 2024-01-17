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

import { Meta, StoryObj } from "@storybook/react";
import { H2, Text } from "@vector-im/compound-web";

import Block from "../Block";

import BlockList from "./BlockList";

const meta = {
  title: "UI/Block List",
  component: BlockList,
} satisfies Meta<typeof BlockList>;

export default meta;

type Story = StoryObj<typeof meta>;

export const Basic: Story = {
  render: (args) => (
    <BlockList {...args}>
      <Block>
        <H2>Block 1</H2>
        <Text>Body 1</Text>
      </Block>
      <Block>
        <H2>Block 2</H2>
        <Text>Body 2</Text>
      </Block>
    </BlockList>
  ),
};
