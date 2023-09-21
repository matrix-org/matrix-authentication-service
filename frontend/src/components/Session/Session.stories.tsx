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
import { Button } from "@vector-im/compound-web";
import { parseISO } from "date-fns";
import { ReactElement } from "react";

import BlockList from "../BlockList/BlockList";

import Session from "./Session";

const meta = {
  title: "UI/Session/Session",
  component: Session,
  tags: ["autodocs"],

  argTypes: {
    createdAt: { control: { type: "date" } },
    finishedAt: { control: { type: "date" } },
    lastActiveAt: { control: { type: "date" } },
  },

  decorators: [
    (Story): ReactElement => (
      <div style={{ width: "378px" }}>
        <BlockList>
          <Story />
        </BlockList>
      </div>
    ),
  ],
} satisfies Meta<typeof Session>;

export default meta;
type Story = StoryObj<typeof Session>;

const defaultProps = {
  id: "oauth2_session:01H5VAGA5NYTKJVXP3HMMKDJQ0",
  createdAt: parseISO("2023-06-29T03:35:17.451292+00:00"),
};

export const BasicSession: Story = {
  args: {
    ...defaultProps,
    name: "KlTqK9CRt3",
    lastActiveIp: "2001:8003:c4614:f501:3091:888a:49c7",
    lastActiveAt: parseISO("2023-07-29T03:35:17.451292+00:00"),
    clientName: "Element",
  },
};

export const BasicFinishedSession: Story = {
  args: {
    ...defaultProps,
    name: "Chrome on Android",
    finishedAt: parseISO("2023-06-30T03:35:17.451292+00:00"),
  },
};

export const WithClientLogo: Story = {
  args: {
    ...defaultProps,
    name: "KlTqK9CRt3",
    clientName: "Element",
    clientLogoUri: "https://element.io/images/logo-mark-primary.svg",
  },
};

export const WithMinimumProps: Story = {
  args: defaultProps,
};

export const WithChildActions: Story = {
  args: {
    ...defaultProps,
    name: "KlTqK9CRt3",
    clientName: "Element",
    clientLogoUri: "https://element.io/images/logo-mark-primary.svg",
    children: (
      <>
        <Button size="sm" onClick={(): void => {}} kind="destructive">
          End session
        </Button>
      </>
    ),
  },
};
