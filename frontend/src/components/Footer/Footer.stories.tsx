// Copyright 2023, 2024 The Matrix.org Foundation C.I.C.
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

import { makeFragmentData } from "../../gql";

import Footer, { FRAGMENT } from "./Footer";

const Template: React.FC<{
  tosUri?: string;
  policyUri?: string;
  imprint?: string;
}> = ({ tosUri, policyUri, imprint }) => (
  <Footer
    siteConfig={makeFragmentData(
      { id: "1234", tosUri, policyUri, imprint },
      FRAGMENT,
    )}
  />
);

const meta = {
  title: "UI/Footer",
  component: Template,
  argTypes: {
    tosUri: {
      control: "text",
    },
    policyUri: {
      control: "text",
    },
    imprint: {
      control: "text",
    },
  },
  tags: ["autodocs"],
} satisfies Meta<typeof Template>;

export default meta;
type Story = StoryObj<typeof Template>;

export const Basic: Story = {
  args: {
    tosUri: "https://matrix.org/legal/terms-and-conditions/",
    policyUri: "https://matrix.org/legal/privacy-notice/",
    imprint: "The Matrix.org Foundation C.I.C.",
  },
};

export const LinksOnly: Story = {
  args: {
    tosUri: "https://matrix.org/legal/terms-and-conditions/",
    policyUri: "https://matrix.org/legal/privacy-notice/",
  },
};

export const ImprintOnly: Story = {
  args: {
    imprint: "The Matrix.org Foundation C.I.C.",
  },
};

export const OneLink: Story = {
  args: {
    tosUri: "https://matrix.org/legal/terms-and-conditions/",
    imprint: "The Matrix.org Foundation C.I.C.",
  },
};
