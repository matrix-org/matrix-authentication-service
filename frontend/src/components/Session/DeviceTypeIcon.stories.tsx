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

import { DeviceType } from "../../gql/graphql";

import DeviceTypeIcon from "./DeviceTypeIcon";

const meta = {
  title: "UI/Session/Device Type Icon",
  component: DeviceTypeIcon,
  tags: ["autodocs"],
  args: {
    deviceType: DeviceType.Unknown,
  },
  argTypes: {
    deviceType: {
      control: "select",
      options: [
        DeviceType.Unknown,
        DeviceType.Pc,
        DeviceType.Mobile,
        DeviceType.Tablet,
      ],
    },
  },
} satisfies Meta<typeof DeviceTypeIcon>;

export default meta;
type Story = StoryObj<typeof DeviceTypeIcon>;

export const Unknown: Story = {};

export const Pc: Story = {
  args: {
    deviceType: DeviceType.Pc,
  },
};
export const Mobile: Story = {
  args: {
    deviceType: DeviceType.Mobile,
  },
};
export const Tablet: Story = {
  args: {
    deviceType: DeviceType.Tablet,
  },
};
