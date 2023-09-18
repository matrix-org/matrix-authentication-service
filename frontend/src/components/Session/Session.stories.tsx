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

import BlockList from "../BlockList/BlockList";

import Session, { SessionProps } from "./Session";

const Template: React.FC<SessionProps> = (props) => {
  return <Session {...props} />;
};

const meta = {
  title: "UI/Session/Session",
  component: Template,
  tags: ["autodocs"],
  decorators: [
    (Story): Element => (
      <div style={{ width: "378px" }}>
        <BlockList>
          <Story />
        </BlockList>
      </div>
    ),
  ],
} satisfies Meta<typeof Template>;

export default meta;
type Story = StoryObj<typeof Template>;

const defaultProps = {
  id: "oauth2_session:01H5VAGA5NYTKJVXP3HMMKDJQ0",
  createdAt: "2023-06-29T03:35:17.451292+00:00",
};

export const BasicSession: Story = {
  args: {
    ...defaultProps,
    name: "KlTqK9CRt3",
    clientName: "Element",
  },
};

export const BasicFinishedSession: Story = {
  args: {
    ...defaultProps,
    name: "Chrome on Android",
    finishedAt: "2023-06-30T03:35:17.451292+00:00",
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
        <Button size="sm" onClick={(): void => {}} kind="desctructive">
          End session
        </Button>
      </>
    ),
  },
};
