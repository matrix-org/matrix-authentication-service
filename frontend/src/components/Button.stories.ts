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

import Button from "./Button";

const meta = {
  title: "UI/Button",
  component: Button,
  tags: ["docsPage"],
  argTypes: {
    onClick: { action: true },
    compact: {
      defaultValue: false,
    },
    ghost: {
      defaultValue: false,
    },
    disabled: {
      defaultValue: false,
    },
  },
} satisfies Meta<typeof Button>;

export default meta;
type Story = StoryObj<typeof Button>;

export const Basic: Story = {
  args: {
    children: "Button",
  },
};

export const Regular: Story = {
  args: {
    children: "Button",
    compact: false,
    ghost: false,
    disabled: false,
  },
};

export const Compact: Story = {
  args: {
    children: "Compact",
    compact: true,
    ghost: false,
    disabled: false,
  },
};

export const Disabled: Story = {
  args: {
    children: "Disabled",
    compact: false,
    ghost: false,
    disabled: true,
  },
};

export const Ghost: Story = {
  args: {
    children: "Ghost",
    compact: false,
    ghost: true,
    disabled: false,
  },
};

export const GhostDisabled: Story = {
  args: {
    children: "Ghost",
    compact: false,
    ghost: true,
    disabled: true,
  },
};
