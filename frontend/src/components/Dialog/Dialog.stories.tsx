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

import { Dialog, Title, Description } from "./Dialog";

const Template: React.FC<{
  title: string;
  description: string;
  asDrawer: boolean;
  open: boolean;
  onOpenChange: (open: boolean) => void;
}> = ({ title, description, asDrawer, open, onOpenChange }) => (
  <Dialog asDrawer={asDrawer} open={open} onOpenChange={onOpenChange}>
    {title && <Title>{title}</Title>}
    <Description>{description}</Description>
  </Dialog>
);

const meta = {
  title: "UI/Dialog",
  component: Template,
  tags: ["autodocs"],
  args: {
    open: true,
    title: "Title",
    description: "Description",
    asDrawer: false,
    onOpenChange: action("onOpenChange"),
  },
  argTypes: {
    open: { control: "boolean" },
    title: { control: "text" },
    description: { control: "text" },
    asDrawer: { control: "boolean" },
    onOpenChange: { action: "onOpenChange" },
  },
} satisfies Meta<typeof Template>;

export default meta;
type Story = StoryObj<typeof Template>;

export const Basic: Story = {};
