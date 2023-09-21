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
import { Button } from "@vector-im/compound-web";
import { PropsWithChildren, ReactElement } from "react";

import SessionListHeader from "./SessionListHeader";

type Props = PropsWithChildren<{
  title: string;
}>;

const NOOP = (): void => {};

const Template: React.FC<Props> = ({ title, children }) => {
  return <SessionListHeader title={title}>{children}</SessionListHeader>;
};

const meta = {
  title: "UI/Session/List header",
  component: Template,
  tags: ["autodocs"],
  decorators: [
    (Story): ReactElement => (
      <div style={{ width: "378px" }}>
        <Story />
      </div>
    ),
  ],
} satisfies Meta<typeof Template>;

export default meta;
type Story = StoryObj<typeof Template>;

export const Basic: Story = {
  args: {
    title: "Apps",
  },
};

export const WithOneAction: Story = {
  args: {
    title: "Apps",
    children: (
      <Button size="sm" kind="destructive" onClick={NOOP}>
        End sessions
      </Button>
    ),
  },
};

export const WithMultipleActions: Story = {
  args: {
    title: "Apps",
    children: (
      <>
        <Button size="sm" kind="secondary" onClick={NOOP}>
          Deselect all
        </Button>
        <Button size="sm" kind="destructive" onClick={NOOP}>
          End sessions
        </Button>
      </>
    ),
  },
};
